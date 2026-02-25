from __future__ import annotations
import requests
from typing import Any, Dict, List, Optional

class GitHubClient:
    def __init__(self, token: str, base_url: str = "https://api.github.com") -> None:
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pr-risk-bot/1.0",
        })

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        r = self.session.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r

    def _post(self, url: str, json: Dict[str, Any]) -> requests.Response:
        r = self.session.post(url, json=json, timeout=30)
        r.raise_for_status()
        return r

    def list_pr_files(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        files: List[Dict[str, Any]] = []
        page = 1
        while True:
            r = self._get(url, params={"per_page": 100, "page": page})
            batch = r.json()
            if not batch:
                break
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return files

    def create_issue_comment(self, owner: str, repo: str, issue_number: int, body: str) -> None:
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        self._post(url, json={"body": body})

    def get_pr(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        return self._get(url).json()
