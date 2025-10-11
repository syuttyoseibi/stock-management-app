#  在庫管理アプリケーション セットアップ＆取扱説明書

## **Part 1: サーバー(Raspberry Pi)設置・運用手順書**
（システムをセットアップする方向け）

### 1. 概要
このドキュメントは、委託在庫管理アプリケーションをRaspberry Pi（ラズパイ）上で構築し、インターネット経由でアクセス可能にするための手順を説明するものです。

### 2. システム構成図
このシステムは、以下の要素で構成されています。

```
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│   利用者（ブラウザ）   │      │  Vercel (LP)     │      │  Supabase DB     │
└──────────────────┘      └──────────────────┘      └──────────────────┘
         │                      │ (URLを問い合わせ)           ▲
         │ 1. LPにアクセス         └──────────────┬──────────┘
         │                                      │ 2. 最新URLを取得
         ▼                                      │
┌───────────────────────────────────────────────┐
│             インターネット経由でシステムにアクセス             │
└───────────────────────────────────────────────┘
         ▲ 3. 取得したURLにアクセス
         │
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  ngrok (トンネル)  │◀────▶│  Docker (アプリ)   │◀────▶│ Pythonスクリプト   │
└──────────────────┘      └──────────────────┘      └──────────────────┘
         │                      │                      │ (ngrokのURLを監視)
         └──────────────────────┴──────────────────────┘
                  ▲ (Raspberry Pi内で実行)
                  │
                  └──────────────────────────────────── 4. URLをSupabaseに更新

```

### 3. 必要なもの
#### ハードウェア
*   Raspberry Pi 4（推奨）
*   MicroSDカード（32GB以上推奨）
*   その他、一般的なラズパイのセットアップ用品

#### ソフトウェア・サービス
*   **Raspberry Pi Imager**
*   **ターミナルソフト** (例: PowerShell, Terminal)
*   **GitHubアカウント:** ソースコード管理
*   **Docker Hubアカウント:** （オプション）
*   **ngrokアカウント:** トンネリングサービス
*   **Supabaseアカウント:** URLを保存するためのデータベース
*   **Vercelアカウント:** ランディングページ(LP)のホスティング

### 4. セットアップ手順
#### ステップ1: Raspberry Piの初期セットアップ
1.  **OSのインストール:** `Raspberry Pi Imager`を使い、`Raspberry Pi OS (64-bit)`をSDカードに書き込みます。SSHを有効化し、ユーザー名とパスワードを設定してください。
2.  **ラズパイの起動とSSH接続:** ラズパイを起動し、PCからSSHで接続します。
    ```shell
    ssh pi@raspberrypi.local
    ```

#### ステップ2: 基本ツールのインストール
ラズパイにログインした状態で、GitとDockerをインストールします。
```shell
# パッケージリストを更新
sudo apt-get update && sudo apt-get upgrade -y

# GitとPython3の環境をインストール
sudo apt-get install -y git python3-pip

# Dockerをインストール
curl -sSL https://get.docker.com | sh
sudo usermod -aG docker pi

# 設定を反映させるため、一度ログアウトして再ログイン
exit
ssh pi@raspberrypi.local
```

#### ステップ3: アプリケーションのセットアップ
1.  **ソースコードの取得:**
    ```shell
    git clone https://github.com/syuttyoseibi/stock-management-app.git
    cd stock-management-app
    ```

2.  **ngrokのセットアップ:**
    *   [ngrokの公式サイト](https://ngrok.com/)でアカウント登録し、Auth Tokenを取得します。
    *   ラズパイで以下のコマンドを実行します。
        ```shell
        # ngrokをインストール
        curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
        echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
        sudo apt update
        sudo apt install ngrok

        # Auth Tokenを設定
        ngrok config add-authtoken <あなたのAuthToken>
        ```

3.  **Supabaseのセットアップ:**
    *   [Supabaseの公式サイト](https://supabase.com/)でプロジェクトを作成します。
    *   **SQL Editor**を開き、以下のクエリを実行してテーブルを作成します。
        ```sql
        CREATE TABLE ngrok_url (
          id BIGINT PRIMARY KEY,
          url TEXT,
          updated_at TIMESTAMPTZ DEFAULT now()
        );
        -- URLを保存するための初期行を挿入
        INSERT INTO ngrok_url (id, url) VALUES (1, 'https://example.com');
        ```
    *   **Project Settings > API** に移動し、以下の2つを控えておきます。
        *   `Project URL`
        *   `service_role` Key (`Project API keys`セクション内)

4.  **環境変数ファイル `.env` の作成:**
    *   `stock-management-app`ディレクトリ直下に`.env`という名前のファイルを作成し、以下の内容を記述します。
        ```
        # SupabaseのプロジェクトURL
        SUPABASE_URL="<あなたのSupabaseプロジェクトURL>"

        # Supabaseのservice_roleキー
        SUPABASE_SERVICE_KEY="<あなたのSupabase service_roleキー>"
        ```

5.  **Pythonスクリプトの依存関係をインストール:**
    ```shell
    pip3 install -r update_ngrok_url_requirements.txt
    ```
    *(注: `update_ngrok_url_requirements.txt`がない場合は、`pip3 install requests python-dotenv supabase` を実行)*

#### ステップ4: アプリケーションの起動
1.  **Dockerイメージのビルド:**
    ```shell
    docker build -t stock-app .
    ```

2.  **Dockerコンテナの起動:**
    *   データベースの永続化のため、ホスト側にディレクトリを作成します。
        ```shell
        mkdir /home/pi/stock-app-data
        ```
    *   コンテナを起動します。これにより、ラズパイ再起動時もアプリが自動で立ち上がります。
        ```shell
        docker run -d -p 3000:3000 -v /home/pi/stock-app-data:/app/data --env-file ./.env --name stock-manager --restart always stock-app
        ```

3.  **ngrokトンネルの起動:**
    *   `tmux`や`screen`などのセッション管理ツール内で実行することを強く推奨します。
        ```shell
        ngrok http 3000
        ```

4.  **URL更新スクリプトの実行:**
    *   別のターミナル（または`tmux`の別ウィンドウ）でスクリプトを実行し、SupabaseにURLが登録されることを確認します。
        ```shell
        python3 update_ngrok_url.py
        ```
    *   **自動化:** cronジョブに登録し、5分おきにURLをチェック・更新するように設定します。
        ```shell
        # crontabを開く
        crontab -e

        # 以下の行を追記して保存
        */5 * * * * /usr/bin/python3 /home/pi/stock-management-app/update_ngrok_url.py >> /home/pi/cron.log 2>&1
        ```

#### ステップ5: Vercelでのランディングページ公開
1.  PCで、`stock-management-app`リポジトリをVercelに連携します。
2.  **Framework Preset**は`Other`を選択します。
3.  **Root Directory**を`landing-page`に設定します。
4.  デプロイを実行します。
5.  デプロイされたURLが、システムの唯一の入口となります。

### 5. アプリケーションの更新方法
1.  ラズパイにSSH接続し、アプリケーションのディレクトリに移動します。
    ```shell
    cd stock-management-app
    ```
2.  最新のソースコードを取得します。
    ```shell
    git pull
    ```
3.  コンテナを再作成します。
    ```shell
    docker stop stock-manager
    docker rm stock-manager
    docker build --no-cache -t stock-app .
    docker run -d -p 3000:3000 -v /home/pi/stock-app-data:/app/data --env-file ./.env --name stock-manager --restart always stock-app
    ```

### 6. データのバックアップと復元
データは`/home/pi/stock-app-data/stock.db`に保存されています。このファイルを定期的にコピーしてバックアップしてください。復元する際は、必ず`docker stop stock-manager`でアプリを停止してからファイルを上書きし、`docker start stock-manager`で再開してください。

---

## **Part 2: アプリケーション取扱説明書**
（実際にシステムを利用する方向け）

### 1. アクセス方法
*   管理者から共有された**ランディングページ（LP）のURL**にアクセスします。
*   LPに表示される「システムへ移動する」ボタンを押すと、ログイン画面に遷移します。

### 2. 主な機能
*   **管理者向け機能:**
    *   全工場の在庫状況と使用履歴の一元管理
    *   工場、部品、ユーザー、従業員などのマスターデータ登録
    *   発注が必要な部品のリストアップ
    *   棚卸しによる在庫数の調整
*   **整備工場ユーザー向け機能:**
    *   自工場の在庫数のリアルタイム確認
    *   部品の使用記録と履歴確認
    *   自工場に所属する従業員の登録・管理

### 3. 管理者ユーザー向けマニュアル
#### 3.1. ログイン
*   **ユーザー名:** `admin`
*   **パスワード:** `password` (初回)
*   **注意:** ログイン後、ご自身の管理者アカウントを別途作成し、初期`admin`アカウントのパスワードを変更または削除することを強く推奨します。

#### 3.2. 各種管理機能
「工場管理」「部品マスタ管理」「ユーザー管理」「従業員管理」「カテゴリー管理」の各タブで、データの追加・編集・削除が可能です。
*   **部品マスタ管理:** CSVファイルを使った一括でのインポート・エクスポート、複数選択しての一括削除も可能です。

#### 3.3. 在庫管理・棚卸し
*   **在庫管理タブ:** 特定工場の在庫の手動更新や、CSVによる全在庫の一括インポートが可能です。
*   **棚卸しタブ:** 工場を選択し、実際の在庫数を入力することで、システム在庫を一括更新できます。

#### 3.4. レポート
*   **発注管理タブ:** 「現在の在庫数」が「最低発注レベル」を下回っている部品を一覧表示します。
*   **レポートタブ:** 期間、工場、部品を指定して、部品の使用履歴を検索できます。

### 4. 整備工場ユーザー向け操作マニュアル
#### 4.1. ログイン
管理者によって作成されたアカウントでログインします。

#### 4.2. 部品の使用
1.  「**部品使用**」タブを開きます。
2.  「整備士」を選択します。
3.  使用した部品の「**使用**」ボタンをタップします。

#### 4.3. 使用履歴の確認
1.  「**使用履歴**」タブを開きます。
2.  月を選択して過去の履歴を確認できます。
3.  間違えた記録は「**取り消し**」ボタンでキャンセルできます。

#### 4.4. 従業員の管理
「**従業員管理**」タブで、自工場に所属する従業員の追加・編集（名前の変更や無効化）ができます。

---

### **付録: CSVインポートフォーマット**
*   文字コードは **UTF-8** で保存してください。
*   1行目は必ず指定のヘッダーにしてください。

#### **A. 部品マスタ用CSV (`部品マスタ管理`タブ)**
```csv
part_number,part_name,category_name
EO-001,エンジンオイル 5W-30,エンジン消耗品
```
*   `part_number` (品番) と `part_name` (品名) は必須です。
*   存在しない `category_name` を指定すると、カテゴリーが自動で作成されます。

#### **B. 在庫情報用CSV (`在庫管理`タブ)**
```csv
part_number,shop_name,quantity,min_reorder_level,location_info
EO-001,A整備工場,20,5,棚A-1
```
*   インポートする前に、`part_number`と`shop_name`がシステムに登録されている必要があります。
*   このCSVの情報に基づき、既存の在庫データが **上書き更新** されます。