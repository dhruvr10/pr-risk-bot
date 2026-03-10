from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("pr_risk_bot.github")


class GitHubClient:
    """Async GitHub REST client backed by httpx."""

    def __init__(self, token: str, base_url: str = "https://api.github.com") -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "pr-risk-bot/1.0",
            },
            timeout=30.0,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
        r = await self._client.get(url, params=params)
        r.raise_for_status()
        return r

    async def _post(self, url: str, payload: Dict[str, Any]) -> httpx.Response:
        r = await self._client.post(url, json=payload)
        r.raise_for_status()
        return r

    async def _patch(self, url: str, payload: Dict[str, Any]) -> httpx.Response:
        r = await self._client.patch(url, json=payload)
        r.raise_for_status()
        return r

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_pr(self, owner: str, repo: str, pr_number: int) -> Dict[str, Any]:
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        return (await self._get(url)).json()

    async def list_pr_files(
        self, owner: str, repo: str, pr_number: int
    ) -> List[Dict[str, Any]]:
        """Fetch all changed files for a PR, handling pagination."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        files: List[Dict[str, Any]] = []
        page = 1
        while True:
            r = await self._get(url, params={"per_page": 100, "page": page})
            batch: List[Dict[str, Any]] = r.json()
            if not batch:
                break
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return files

    async def list_issue_comments(
        self, owner: str, repo: str, issue_number: int
    ) -> List[Dict[str, Any]]:
        """Return all comments on an issue/PR."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        comments: List[Dict[str, Any]] = []
        page = 1
        while True:
            r = await self._get(url, params={"per_page": 100, "page": page})
            batch: List[Dict[str, Any]] = r.json()
            if not batch:
                break
            comments.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return comments

    async def find_bot_comment(
        self, owner: str, repo: str, pr_number: int, signature: str
    ) -> Optional[int]:
        """Return the comment ID of an existing bot comment, or None."""
        comments = await self.list_issue_comments(owner, repo, pr_number)
        for c in comments:
            if signature in (c.get("body") or ""):
                return int(c["id"])
        return None

    async def create_issue_comment(
        self, owner: str, repo: str, issue_number: int, body: str
    ) -> None:
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        await self._post(url, {"body": body})

    async def update_issue_comment(
        self, owner: str, repo: str, comment_id: int, body: str
    ) -> None:
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/comments/{comment_id}"
        await self._patch(url, {"body": body})
