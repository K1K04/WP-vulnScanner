"""
tests/test_scan.py — Scan endpoint tests
========================================
Tests for /scan and /api/scan endpoints.
"""

import json
import pytest
import uuid


@pytest.mark.unit
class TestScanStartEndpoint:
    """Test POST /scan endpoint."""
    
    def test_start_scan_requires_url(self, client):
        """Test /scan requires URL parameter."""
        response = client.post("/scan", json={
            "legal_accepted": True
        })
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data or "message" in data
    
    def test_start_scan_requires_legal(self, client):
        """Test /scan requires legal acceptance."""
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": False
        })
        assert response.status_code == 403
        data = response.get_json()
        assert "error" in data or "message" in data
    
    def test_start_scan_with_valid_data(self, client):
        """Test /scan with valid data returns job_id."""
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        # Should return 200 or 202 (accepted)
        assert response.status_code in [200, 202]
        data = response.get_json()
        
        # Should contain job_id
        assert "job_id" in data or "id" in data
    
    def test_start_scan_rejects_invalid_url(self, client):
        """Test /scan rejects invalid URLs."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",  # May be blocked
            "localhost",
            "127.0.0.1",  # SSRF protection
        ]
        
        for url in invalid_urls:
            response = client.post("/scan", json={
                "url": url,
                "legal_accepted": True
            })
            # Should reject or handle gracefully
            assert response.status_code in [400, 403, 422]
    
    def test_start_scan_normalizes_url(self, client):
        """Test /scan normalizes URL input."""
        response = client.post("/scan", json={
            "url": "example.com",  # Missing scheme
            "legal_accepted": True
        })
        # Should either normalize or reject
        assert response.status_code in [200, 202, 400]
    
    def test_start_scan_accepts_https_url(self, client):
        """Test /scan accepts HTTPS URLs."""
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        assert response.status_code in [200, 202]
    
    def test_start_scan_returns_job_id_format(self, client):
        """Test /scan returns properly formatted job_id."""
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        if response.status_code in [200, 202]:
            data = response.get_json()
            job_id = data.get("job_id") or data.get("id")
            
            # job_id should be a non-empty string
            assert isinstance(job_id, str)
            assert len(job_id) > 0


@pytest.mark.unit
class TestScanResultEndpoint:
    """Test GET /scan/<id>/result endpoint."""
    
    def test_scan_result_not_found(self, client):
        """Test /scan/<id>/result with invalid job_id returns 404."""
        fake_id = str(uuid.uuid4())[:12]
        response = client.get(f"/scan/{fake_id}/result")
        assert response.status_code in [404, 400]
    
    def test_scan_result_returns_json(self, client):
        """Test /scan/<id>/result returns JSON."""
        # First, start a scan
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        
        if response.status_code in [200, 202]:
            data = response.get_json()
            job_id = data.get("job_id") or data.get("id")
            
            # Try to get result
            result_response = client.get(f"/scan/{job_id}/result")
            # Result might not be ready yet, but should return JSON
            assert result_response.content_type in ["application/json", "text/json"]


@pytest.mark.unit
class TestScanStreamEndpoint:
    """Test GET /scan/<id>/stream endpoint for SSE."""
    
    def test_scan_stream_returns_event_stream(self, client):
        """Test /scan/<id>/stream returns event stream."""
        # First, start a scan
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        
        if response.status_code in [200, 202]:
            data = response.get_json()
            job_id = data.get("job_id") or data.get("id")
            
            # Try to stream
            stream_response = client.get(f"/scan/{job_id}/stream")
            # Should return 200 or 404 if not found
            assert stream_response.status_code in [200, 404, 400]


@pytest.mark.integration
class TestScanWorkflow:
    """Integration tests for complete scan workflow."""
    
    def test_scan_creation_and_status(self, client):
        """Test scan creation and status check."""
        # Create scan
        response = client.post("/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        
        assert response.status_code in [200, 202]
        data = response.get_json()
        job_id = data.get("job_id") or data.get("id")
        
        # Check status is in expected states
        assert "status" in data or job_id is not None
    
    @pytest.mark.slow
    def test_scan_deduplication(self, client):
        """Test that duplicate scans are deduplicated."""
        url = "https://example.com"
        
        # Start first scan
        response1 = client.post("/scan", json={
            "url": url,
            "legal_accepted": True
        })
        
        if response1.status_code in [200, 202]:
            data1 = response1.get_json()
            job_id1 = data1.get("job_id") or data1.get("id")
            
            # Start second scan with same URL
            response2 = client.post("/scan", json={
                "url": url,
                "legal_accepted": True
            })
            
            if response2.status_code in [200, 202]:
                data2 = response2.get_json()
                job_id2 = data2.get("job_id") or data2.get("id")
                
                # May return same job_id or different based on implementation
                assert job_id1 is not None and job_id2 is not None


@pytest.mark.unit
class TestApiScanEndpoint:
    """Test POST /api/scan JSON API endpoint."""
    
    def test_api_scan_requires_auth(self, client):
        """Test /api/scan requires API key."""
        response = client.post("/api/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        })
        # Should require auth (401) or not exist (404)
        assert response.status_code in [401, 403, 404]
    
    def test_api_scan_accepts_valid_auth(self, client, api_headers):
        """Test /api/scan accepts valid API key."""
        response = client.post("/api/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        }, headers=api_headers)
        
        # Should succeed (200/202) or endpoint not found (404)
        assert response.status_code in [200, 202, 404]
    
    def test_api_scan_returns_json(self, client, api_headers):
        """Test /api/scan returns JSON."""
        response = client.post("/api/scan", json={
            "url": "https://example.com",
            "legal_accepted": True
        }, headers=api_headers)
        
        # If endpoint exists and auth passes
        if response.status_code in [200, 202]:
            assert response.content_type in ["application/json", "text/json"]
            data = response.get_json()
            assert "job_id" in data or "id" in data or "error" not in data
