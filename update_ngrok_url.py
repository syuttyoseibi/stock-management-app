import os
import sys
import requests
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables from .env file
load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

# Check if Supabase credentials are set
if not SUPABASE_URL or not SUPABASE_KEY:
    print("エラー: SUPABASE_URL と SUPABASE_SERVICE_KEY が .env ファイルに設定されていません。")
    sys.exit(1)

# Initialize Supabase client
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    print(f"Supabaseクライアントの初期化中にエラーが発生しました: {e}")
    sys.exit(1)

def get_ngrok_url():
    """Query the local ngrok API to get the public HTTPS URL."""
    try:
        response = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=5)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        tunnels = response.json().get("tunnels", [])
        
        for tunnel in tunnels:
            if tunnel.get("proto") == "https":
                return tunnel.get("public_url")
        
        return None # No HTTPS tunnel found
    except requests.exceptions.ConnectionError:
        # This error occurs if the ngrok service is not running
        return None
    except Exception as e:
        print(f"ngrok APIからのURL取得中に予期せぬエラーが発生しました: {e}")
        return None

def update_supabase_url(url):
    """Update the ngrok_url table in Supabase with the new URL."""
    if not url:
        print("更新するURLがありません。")
        return

    try:
        # Supabase-py v2 returns a single response object
        response = supabase.table("ngrok_url").update({"url": url}).eq("id", 1).execute()
        
        # Check if the response object has an error attribute and if it's not None
        if hasattr(response, 'error') and response.error:
            raise Exception(f"API Error: {response.error.message}")
        
        print(f"SupabaseのURLを正常に更新しました: {url}")

    except Exception as e:
        print(f"Supabaseの更新中にエラーが発生しました: {e}")

if __name__ == "__main__":
    print("ngrokの公開URLを取得しています...")
    ngrok_url = get_ngrok_url()
    
    if ngrok_url:
        print(f"現在の公開URLを発見しました: {ngrok_url}")
        update_supabase_url(ngrok_url)
    else:
        print("ngrokのHTTPSトンネルが見つかりませんでした。ngrokが正しく実行されているか確認してください。")
