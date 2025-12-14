"""
Event emitter using Redis pub/sub.

Publishes events to 'auth.events' channel for consumption by Library Service
and other downstream services.
"""
import json
import logging
from typing import Optional

from app.events.event_schemas import EventType
from app.redis_client import get_redis

logger = logging.getLogger(__name__)

EVENTS_CHANNEL = "auth.events"


async def emit_event(event: EventType) -> bool:
    """
    Emit an event to Redis pub/sub channel.
    
    Args:
        event: Event object (must be a subclass of BaseEvent)
        
    Returns:
        True if event was published successfully, False otherwise
        
    Note:
        If Redis is not available, logs error but does not raise exception
        to prevent event emission failures from blocking user operations.
    """
    try:
        redis = await get_redis()
        if redis is None:
            logger.warning(
                f"Redis not available, cannot emit event: {event.event} "
                f"(user_id: {getattr(event, 'user_id', 'N/A')})"
            )
            return False
        
        # Serialize event to JSON
        payload = event.model_dump_json()
        
        # Publish to Redis channel
        subscribers = await redis.publish(EVENTS_CHANNEL, payload)
        
        logger.info(
            f"Emitted event: {event.event} to {subscribers} subscriber(s) "
            f"(user_id: {getattr(event, 'user_id', 'N/A')})"
        )
        
        return True
        
    except Exception as e:
        logger.error(
            f"Failed to emit event: {event.event} "
            f"(user_id: {getattr(event, 'user_id', 'N/A')}): {e}",
            exc_info=True
        )
        return False


async def emit_event_dict(event_type: str, payload: dict) -> bool:
    """
    Convenience function to emit event from dict payload.
    
    Args:
        event_type: Event type string (e.g., "user.created")
        payload: Event data as dictionary
        
    Returns:
        True if event was published successfully, False otherwise
        
    Note:
        This is a simpler interface for cases where constructing
        the full Pydantic schema is inconvenient. Validation is skipped.
    """
    try:
        redis = await get_redis()
        if redis is None:
            logger.warning(
                f"Redis not available, cannot emit event: {event_type} "
                f"(user_id: {payload.get('user_id', 'N/A')})"
            )
            return False
        
        # Add event type and timestamp if not present
        if "event" not in payload:
            payload["event"] = event_type
        if "timestamp" not in payload:
            from datetime import datetime
            payload["timestamp"] = datetime.now().isoformat()
        
        # Serialize to JSON
        message = json.dumps(payload, default=str)
        
        # Publish to Redis channel
        subscribers = await redis.publish(EVENTS_CHANNEL, message)
        
        logger.info(
            f"Emitted event: {event_type} to {subscribers} subscriber(s) "
            f"(user_id: {payload.get('user_id', 'N/A')})"
        )
        
        return True
        
    except Exception as e:
        logger.error(
            f"Failed to emit event: {event_type} "
            f"(user_id: {payload.get('user_id', 'N/A')}): {e}",
            exc_info=True
        )
        return False
