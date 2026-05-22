"""
tests/test_db.py — Database operation tests
===========================================
Tests for database operations and persistence.
"""

import json
import pytest
import sqlite3


@pytest.mark.unit
class TestDatabaseSetup:
    """Test database initialization and schema."""
    
    def test_test_db_fixture_creates_tables(self, test_db):
        """Test that test_db fixture creates required tables."""
        cursor = test_db.cursor()
        
        # Check if scans table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        assert cursor.fetchone() is not None
        
        # Check if scan_jobs table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_jobs'")
        assert cursor.fetchone() is not None
    
    def test_database_has_correct_schema(self, test_db):
        """Test that database tables have correct schema."""
        cursor = test_db.cursor()
        
        # Get scans table columns
        cursor.execute("PRAGMA table_info(scans)")
        columns = [row[1] for row in cursor.fetchall()]
        
        assert "id" in columns
        assert "url" in columns
    
    def test_database_pragma_settings(self, test_db):
        """Test that WAL mode is enabled."""
        cursor = test_db.cursor()
        cursor.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        
        assert mode.upper() == "WAL"


@pytest.mark.unit
class TestDatabaseInsertions:
    """Test inserting data into database."""
    
    def test_insert_scan_record(self, test_db):
        """Test inserting a scan record."""
        scan_id = "test_scan_001"
        url = "https://example.com"
        
        cursor = test_db.cursor()
        cursor.execute(
            "INSERT INTO scans (id, url, result_json) VALUES (?, ?, ?)",
            (scan_id, url, json.dumps({"status": "completed"}))
        )
        test_db.commit()
        
        # Verify insert
        cursor.execute("SELECT url FROM scans WHERE id = ?", (scan_id,))
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == url
    
    def test_insert_job_state(self, test_db):
        """Test inserting job state record."""
        job_id = "test_job_001"
        url = "https://example.com"
        
        cursor = test_db.cursor()
        cursor.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            (job_id, url, "running")
        )
        test_db.commit()
        
        # Verify insert
        cursor.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,))
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == "running"
    
    def test_insert_pwa_cache(self, test_db):
        """Test inserting PWA cache entry."""
        url = "https://example.com"
        scan_id = "test_scan_001"
        
        cursor = test_db.cursor()
        cursor.execute(
            "INSERT INTO pwa_cache (url, scan_id, result_json) VALUES (?, ?, ?)",
            (url, scan_id, json.dumps({"data": "cached"}))
        )
        test_db.commit()
        
        # Verify insert
        cursor.execute("SELECT scan_id FROM pwa_cache WHERE url = ?", (url,))
        result = cursor.fetchone()
        assert result is not None
        assert result[0] == scan_id


@pytest.mark.unit
class TestDatabaseQueries:
    """Test querying data from database."""
    
    def test_query_scan_by_id(self, test_db):
        """Test querying a scan by ID."""
        scan_id = "test_scan_002"
        url = "https://example.com"
        
        # Insert test data
        cursor = test_db.cursor()
        cursor.execute(
            "INSERT INTO scans (id, url) VALUES (?, ?)",
            (scan_id, url)
        )
        test_db.commit()
        
        # Query it back
        cursor.execute("SELECT url FROM scans WHERE id = ?", (scan_id,))
        result = cursor.fetchone()
        
        assert result is not None
        assert result[0] == url
    
    def test_query_multiple_scans(self, test_db):
        """Test querying multiple scans."""
        cursor = test_db.cursor()
        
        # Insert multiple records
        for i in range(3):
            cursor.execute(
                "INSERT INTO scans (id, url) VALUES (?, ?)",
                (f"scan_{i}", f"https://example{i}.com")
            )
        test_db.commit()
        
        # Query all
        cursor.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        
        assert count >= 3
    
    def test_query_job_by_status(self, test_db):
        """Test querying jobs by status."""
        cursor = test_db.cursor()
        
        # Insert job with status
        cursor.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            ("job_1", "https://example.com", "running")
        )
        test_db.commit()
        
        # Query by status
        cursor.execute("SELECT id FROM scan_jobs WHERE status = ?", ("running",))
        result = cursor.fetchone()
        
        assert result is not None


@pytest.mark.unit
class TestDatabaseUpdates:
    """Test updating data in database."""
    
    def test_update_job_status(self, test_db):
        """Test updating job status."""
        job_id = "job_update_1"
        
        cursor = test_db.cursor()
        
        # Insert initial record
        cursor.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            (job_id, "https://example.com", "pending")
        )
        test_db.commit()
        
        # Update status
        cursor.execute(
            "UPDATE scan_jobs SET status = ? WHERE id = ?",
            ("completed", job_id)
        )
        test_db.commit()
        
        # Verify update
        cursor.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,))
        result = cursor.fetchone()
        assert result[0] == "completed"
    
    def test_update_with_result(self, test_db):
        """Test updating job with result."""
        job_id = "job_result_1"
        result_data = {"findings": [{"type": "vulnerability"}]}
        
        cursor = test_db.cursor()
        
        # Insert initial record
        cursor.execute(
            "INSERT INTO scan_jobs (id, url, status) VALUES (?, ?, ?)",
            (job_id, "https://example.com", "pending")
        )
        test_db.commit()
        
        # Update with result
        cursor.execute(
            "UPDATE scan_jobs SET status = ?, result_json = ? WHERE id = ?",
            ("done", json.dumps(result_data), job_id)
        )
        test_db.commit()
        
        # Verify update
        cursor.execute("SELECT result_json FROM scan_jobs WHERE id = ?", (job_id,))
        result = cursor.fetchone()
        assert result[0] is not None
        loaded = json.loads(result[0])
        assert "findings" in loaded


@pytest.mark.integration
class TestDatabaseTransactions:
    """Test database transaction handling."""
    
    def test_transaction_commit(self, test_db):
        """Test that committed transactions persist."""
        cursor = test_db.cursor()
        
        # Insert and commit
        cursor.execute(
            "INSERT INTO scans (id, url) VALUES (?, ?)",
            ("trans_1", "https://example.com")
        )
        test_db.commit()
        
        # Create new connection and verify
        import tempfile
        import os
        db_path = test_db.execute("PRAGMA database_list").fetchone()[2]
        
        if os.path.exists(db_path):
            new_conn = sqlite3.connect(db_path)
            new_cursor = new_conn.cursor()
            new_cursor.execute("SELECT url FROM scans WHERE id = ?", ("trans_1",))
            result = new_cursor.fetchone()
            new_conn.close()
            
            assert result is not None
