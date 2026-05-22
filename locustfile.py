"""
locustfile.py — Load testing for WP VulnScanner with Locust
=========================================================
Simulates realistic user behavior under load.

Run with: locust -f locustfile.py --host=http://localhost:5000
"""

from __future__ import annotations

import time
import uuid
from random import choice, uniform

from locust import HttpUser, TaskSet, task, between, events
import logging

log = logging.getLogger("locust")


class ScanUserBehavior(TaskSet):
    """User behavior for scan operations."""
    
    def on_start(self):
        """Called when user starts."""
        self.job_ids = []
        self.test_urls = [
            "https://example.com",
            "https://wordpress.org",
            "https://wordpress.com",
        ]
    
    @task(3)
    def initiate_scan(self):
        """Task: Initiate a new scan (weight: 3)."""
        url = choice(self.test_urls)
        
        response = self.client.post(
            "/scan",
            json={
                "url": url,
                "legal_accepted": True,
                "force_rescan": False,
            },
            timeout=10,
        )
        
        if response.status_code in [200, 202]:
            try:
                data = response.json()
                if "job_id" in data:
                    self.job_ids.append(data["job_id"])
                    log.info(f"Initiated scan: {data['job_id']} for {url}")
            except Exception as e:
                log.error(f"Failed to parse scan response: {e}")
    
    @task(2)
    def check_scan_status(self):
        """Task: Check status of existing scan (weight: 2)."""
        if not self.job_ids:
            return
        
        job_id = choice(self.job_ids)
        
        response = self.client.get(
            f"/scan/{job_id}/result",
            timeout=5,
        )
        
        if response.status_code == 200:
            try:
                data = response.json()
                status = data.get("status") or data.get("scan_id")
                log.info(f"Scan status: {status}")
            except Exception as e:
                log.debug(f"Failed to parse status response: {e}")
    
    @task(1)
    def stream_scan_progress(self):
        """Task: Stream scan progress (weight: 1)."""
        if not self.job_ids:
            return
        
        job_id = choice(self.job_ids[-5:]) if len(self.job_ids) > 5 else choice(self.job_ids)
        
        try:
            response = self.client.get(
                f"/scan/{job_id}/stream",
                stream=True,
                timeout=5,
            )
            
            if response.status_code == 200:
                # Read a few events from stream
                lines_read = 0
                for line in response.iter_lines():
                    lines_read += 1
                    if lines_read >= 5:  # Only read first 5 events
                        break
        except Exception as e:
            log.debug(f"Stream interrupted: {e}")
    
    @task(1)
    def health_check(self):
        """Task: Check app health (weight: 1)."""
        response = self.client.get(
            "/health",
            timeout=5,
        )
        
        if response.status_code == 200:
            log.debug("Health check OK")
    
    @task(1)
    def api_scan_request(self):
        """Task: Make API scan request with auth (weight: 1)."""
        url = choice(self.test_urls)
        
        # Assume API key is set via environment
        headers = {
            "Authorization": "Bearer test-api-key",
            "Content-Type": "application/json",
        }
        
        response = self.client.post(
            "/api/scan",
            json={
                "url": url,
                "legal_accepted": True,
            },
            headers=headers,
            timeout=10,
        )
        
        if response.status_code in [200, 202, 401, 403, 404]:
            log.debug(f"API scan response: {response.status_code}")


class ScanUser(HttpUser):
    """Represents a user performing scan operations."""
    
    tasks = [ScanUserBehavior]
    wait_time = between(2, 5)  # Wait 2-5 seconds between tasks


class DashboardUserBehavior(TaskSet):
    """User behavior for dashboard browsing."""
    
    @task(1)
    def view_dashboard(self):
        """Task: View main dashboard."""
        response = self.client.get("/dashboard", timeout=5)
        log.debug(f"Dashboard response: {response.status_code}")
    
    @task(1)
    def view_history(self):
        """Task: View scan history."""
        response = self.client.get("/history", timeout=5)
        log.debug(f"History response: {response.status_code}")
    
    @task(1)
    def view_vulns_db(self):
        """Task: View vulnerabilities database."""
        response = self.client.get("/vulns-db", timeout=5)
        log.debug(f"Vulns DB response: {response.status_code}")


class DashboardUser(HttpUser):
    """Represents a user browsing the dashboard."""
    
    tasks = [DashboardUserBehavior]
    wait_time = between(3, 8)


class ApiLoadTest(TaskSet):
    """API load test without UI."""
    
    def on_start(self):
        """Called when user starts."""
        self.scan_ids = []
    
    @task(5)
    def api_create_scan(self):
        """Task: Create scan via API."""
        response = self.client.post(
            "/api/scan",
            json={
                "url": "https://example.com",
                "legal_accepted": True,
            },
            timeout=10,
        )
        
        if response.status_code in [200, 202]:
            try:
                data = response.json()
                if "job_id" in data:
                    self.scan_ids.append(data["job_id"])
            except Exception:
                pass
    
    @task(3)
    def api_get_status(self):
        """Task: Get scan status via API."""
        if self.scan_ids:
            scan_id = choice(self.scan_ids)
            response = self.client.get(
                f"/scan/{scan_id}/result",
                timeout=5,
            )


class ApiUser(HttpUser):
    """Represents an API client."""
    
    tasks = [ApiLoadTest]
    wait_time = between(1, 3)


# ──── Event Handlers ───────────────────────────────────────────────

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called at test start."""
    log.info("🚀 Load test starting...")
    log.info(f"🎯 Target: {environment.host}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called at test end."""
    log.info("✅ Load test completed")


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Called on each request."""
    if exception:
        log.warning(f"❌ {request_type} {name}: {exception}")
    else:
        log.debug(f"✓ {request_type} {name}: {response_time}ms")
