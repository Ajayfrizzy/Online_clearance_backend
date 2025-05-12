import unittest
from app import app, db, create_super_admin, Staff

class TestSystem(unittest.TestCase):
    def setUp(self):
        # Configure test environment
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://neondb_owner:npg_B1fTMGAEU8nq@ep-shiny-tree-a4ee97lq-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require'
        app.config['TESTING'] = True  # This suppresses the admin creation message
        
        # Push application context
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Create all tables
        db.create_all()
        
        # Clear any existing admin (important for test isolation)
        Staff.query.filter_by(staff_id='SupAdmin').delete()
        db.session.commit()
        
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_super_admin_creation(self):
        # Verify no admin exists initially
        self.assertIsNone(Staff.query.filter_by(staff_id='SupAdmin').first())
        
        # Test creation
        create_super_admin()
        
        # Verify admin was created
        admin = Staff.query.filter_by(staff_id='SupAdmin').first()
        self.assertIsNotNone(admin)
        self.assertEqual(admin.role, 'super_admin')

if __name__ == '__main__':
    unittest.main(warnings='ignore')  # Clean test output