const request = require('supertest');
const { app, initializeDatabase, db } = require('../server');

describe('Stock Management API', () => {
    let adminAgent; // Agent for admin user
    let shopUserAgent; // Agent for shop user
    let testShopId;
    let testPartId;
    let testEmployeeId;
    let testUsageId;

    beforeAll(async () => {
        await initializeDatabase();
        adminAgent = request.agent(app);
        shopUserAgent = request.agent(app);

        // Log in as admin
        await adminAgent
            .post('/api/login')
            .send({ username: 'admin', password: 'password' });

        // Create a shop for the shop user
        const shopRes = await adminAgent
            .post('/api/admin/shops')
            .send({ name: 'Test Shop' });
        testShopId = shopRes.body.id;

        // Create a shop user
        await adminAgent
            .post('/api/admin/users')
            .send({ username: 'testuser', password: 'password', role: 'shop_user', shop_id: testShopId });

        // Log in as shop user
        await shopUserAgent
            .post('/api/login')
            .send({ username: 'testuser', password: 'password' });
        
        // Create a part for testing
        const partRes = await adminAgent
            .post('/api/admin/parts')
            .send({ part_number: 'TEST-001', part_name: 'Test Part' });
        testPartId = partRes.body.id;

        // Add inventory for the test part
        await adminAgent
            .post('/api/admin/inventory')
            .send({ shop_id: testShopId, part_id: testPartId, quantity: 10, min_reorder_level: 2 });

        // Create an employee for the shop
        const employeeRes = await adminAgent
            .post('/api/admin/employees')
            .send({ name: 'Test Employee', shop_id: testShopId });
        testEmployeeId = employeeRes.body.id;
    });

    afterAll((done) => {
        db.close(done);
    });

    describe('Authentication', () => {
        it('should fail to login with wrong credentials', async () => {
            const res = await request(app)
                .post('/api/login')
                .send({ username: 'admin', password: 'wrongpassword' });
            expect(res.statusCode).toEqual(401);
        });

        it('should login successfully as admin', async () => {
            const res = await request.agent(app)
                .post('/api/login')
                .send({ username: 'admin', password: 'password' });
            expect(res.statusCode).toEqual(200);
            expect(res.body.user.role).toBe('admin');
        });
    });

    describe('Shop User Operations', () => {
        it('should get inventory for their own shop', async () => {
            const res = await shopUserAgent.get(`/api/shops/${testShopId}/inventory`);
            expect(res.statusCode).toEqual(200);
            expect(Array.isArray(res.body)).toBe(true);
            const testPart = res.body.find(p => p.id === testPartId);
            expect(testPart).toBeDefined();
            expect(testPart.quantity).toBe(10);
        });

        it('should use a part from their shop', async () => {
            const res = await shopUserAgent
                .post('/api/use-part')
                .send({ part_id: testPartId, shop_id: testShopId, employee_id: testEmployeeId });
            expect(res.statusCode).toEqual(200);
            expect(res.body.stock_left).toBe(9);
        });

        it('should see the usage in their history', async () => {
            const now = new Date();
            const month = `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
            const res = await shopUserAgent.get(`/api/usage-history?month=${month}`);
            expect(res.statusCode).toEqual(200);
            expect(res.body.length).toBeGreaterThan(0);
            const usage = res.body.find(h => h.part_number === 'TEST-001');
            expect(usage).toBeDefined();
            expect(usage.employee_name).toBe('Test Employee');
            testUsageId = usage.id; // Save for cancellation test
        });

        it('should cancel a usage entry', async () => {
            const res = await shopUserAgent
                .post('/api/cancel-usage')
                .send({ usage_id: testUsageId, reason: 'Test cancellation' });
            expect(res.statusCode).toEqual(200);
            expect(res.body.message).toContain('cancelled');
        });

        it('should have the inventory restored after cancellation', async () => {
            const res = await shopUserAgent.get(`/api/shops/${testShopId}/inventory`);
            const testPart = res.body.find(p => p.id === testPartId);
            expect(testPart.quantity).toBe(10);
        });
    });

    describe('Admin Operations', () => {
        it('should get a list of all parts', async () => {
            const res = await adminAgent.get('/api/admin/parts');
            expect(res.statusCode).toEqual(200);
            expect(res.body.length).toBeGreaterThan(0);
        });

        it('should get a list of all inventory', async () => {
            const res = await adminAgent.get('/api/admin/all-inventory');
            expect(res.statusCode).toEqual(200);
            expect(res.body.length).toBeGreaterThan(0);
        });

        it('should get a reorder list', async () => {
            // First, update a part to be below reorder level
            await adminAgent.post('/api/admin/inventory').send({ shop_id: testShopId, part_id: testPartId, quantity: 1, min_reorder_level: 5 });
            const res = await adminAgent.get('/api/admin/reorder-list');
            expect(res.statusCode).toEqual(200);
            const reorderItem = res.body.find(item => item.part_number === 'TEST-001');
            expect(reorderItem).toBeDefined();
            expect(reorderItem.shortage).toBe(4);
            // Reset inventory
            await adminAgent.post('/api/admin/inventory').send({ shop_id: testShopId, part_id: testPartId, quantity: 10, min_reorder_level: 2 });
        });

        it('should perform a stocktake', async () => {
            const stocktakeData = [{ part_id: testPartId, actual_quantity: 8 }];
            const res = await adminAgent
                .post('/api/admin/inventory/stocktake')
                .send({ shop_id: testShopId, stocktakeData });
            expect(res.statusCode).toEqual(200);
            expect(res.body.message).toContain('1 items updated');

            // Verify the change
            const invRes = await adminAgent.get('/api/admin/all-inventory');
            const updatedItem = invRes.body.find(i => i.part_id === testPartId && i.shop_id === testShopId);
            expect(updatedItem.quantity).toBe(8);
        });
    });
});