"""
RSS/Atom feed collector — CCCS, threat blogs, hacker news.
"""
import feedparser
import httpx
from loguru import logger
from config import cfg

RSS_FEEDS = cfg["rss_feeds"]


def collect_rss_feeds() -> list[dict]:
    results = []
    for feed_url in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries:
                text = entry.get("summary", "") + " " + entry.get("title", "")
                results.append({
                    "source_url": entry.get("link", feed_url),
                    "source_type": "rss",
                    "raw_text": text,
                    "title": entry.get("title", ""),
                })
            logger.info(f"Collected {len(feed.entries)} entries from {feed_url}")
        except Exception as e:
            logger.warning(f"RSS feed failed {feed_url}: {e}")
    return results
