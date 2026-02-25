"""
MongoDB database layer using Motor async driver.
Includes fallback to in-memory storage if MongoDB is unreachable.
"""

import os
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class InMemoryStorage:
    """
    Fallback in-memory storage when MongoDB is unavailable.
    Not persistent across restarts - use for temporary backup only.
    """
    
    def __init__(self):
        self._conversations: Dict[str, Dict[str, Any]] = {}
    
    async def get_conversation(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._conversations.get(session_id)
    
    async def save_conversation(self, session_id: str, data: Dict[str, Any]) -> None:
        self._conversations[session_id] = data
    
    async def update_conversation(self, session_id: str, messages: List[Dict], intelligence: Dict[str, Any]) -> None:
        if session_id not in self._conversations:
            self._conversations[session_id] = {
                "sessionId": session_id,
                "createdAt": datetime.utcnow(),
                "messages": [],
                "intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": [],
                    "agentNotes": ""
                },
                "messageCount": 0
            }
        
        self._conversations[session_id]["messages"].extend(messages)
        self._conversations[session_id]["messageCount"] = len(self._conversations[session_id]["messages"])
        
        # Merge intelligence
        intel = self._conversations[session_id]["intelligence"]
        for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            if key in intelligence:
                existing = set(intel.get(key, []))
                new_items = set(intelligence.get(key, []))
                intel[key] = list(existing.union(new_items))
        
        if intelligence.get("agentNotes"):
            intel["agentNotes"] = intelligence["agentNotes"]
        
        self._conversations[session_id]["updatedAt"] = datetime.utcnow()
    
    async def get_all_intelligence(self) -> List[Dict[str, Any]]:
        return [
            {
                "sessionId": sid,
                "intelligence": data.get("intelligence", {}),
                "messageCount": data.get("messageCount", 0)
            }
            for sid, data in self._conversations.items()
        ]


class DatabaseManager:
    """
    MongoDB connection manager with in-memory fallback.
    Uses Motor async driver for non-blocking database operations.
    """
    
    def __init__(self):
        self.mongodb_uri = os.getenv("MONGODB_URI", "").strip()
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.in_memory = InMemoryStorage()
        self._use_in_memory = False
        self._connection_verified = False
    
    async def connect(self) -> bool:
        """
        Establish MongoDB connection. Falls back to in-memory if unavailable.
        Returns True if connected to MongoDB, False if using in-memory fallback.
        """
        if not self.mongodb_uri:
            logger.warning("MONGODB_URI not set. Using in-memory storage.")
            self._use_in_memory = True
            return False
        
        try:
            self.client = AsyncIOMotorClient(
                self.mongodb_uri,
                serverSelectionTimeoutMS=5000,  # 5 second timeout
                connectTimeoutMS=5000
            )
            # Verify connection by pinging
            await self.client.admin.command("ping")
            self.db = self.client.get_database("honeypot")
            self._connection_verified = True
            self._use_in_memory = False
            logger.info("SUCCESS: Connected to MongoDB Atlas")
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.warning(f"ERROR: Database connection failed ({e}), using fallback")
            self._use_in_memory = True
            self.client = None
            return False
        except Exception as e:
            logger.error(f"ERROR: Unexpected database error ({e}), using fallback")
            self._use_in_memory = True
            return False
    
    async def verify_connection(self) -> bool:
        """
        Verify connection is still alive. Switch to in-memory if not.
        """
        if self._use_in_memory:
            return False
        
        if not self.client:
            return await self.connect()
        
        try:
            await self.client.admin.command("ping")
            return True
        except Exception as e:
            logger.warning(f"MongoDB connection lost: {e}. Switching to in-memory.")
            self._use_in_memory = True
            return False
    
    async def get_conversation(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch conversation by session ID."""
        if self._use_in_memory:
            return await self.in_memory.get_conversation(session_id)
        
        try:
            conversation = await self.db.conversations.find_one({"sessionId": session_id})
            if conversation:
                conversation["_id"] = str(conversation["_id"])  # Convert ObjectId to string
            return conversation
        except Exception as e:
            logger.error(f"Error fetching conversation: {e}")
            await self.verify_connection()
            return await self.in_memory.get_conversation(session_id)
    
    async def save_conversation(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Create new conversation document."""
        if self._use_in_memory:
            await self.in_memory.save_conversation(session_id, {
                "sessionId": session_id,
                "createdAt": datetime.utcnow(),
                "metadata": metadata,
                "messages": [],
                "intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": [],
                    "agentNotes": ""
                },
                "messageCount": 0
            })
            return True
        
        try:
            conversation_doc = {
                "sessionId": session_id,
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow(),
                "metadata": metadata,
                "messages": [],
                "intelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": [],
                    "agentNotes": ""
                },
                "messageCount": 0
            }
            await self.db.conversations.insert_one(conversation_doc)
            return True
        except Exception as e:
            logger.error(f"Error saving conversation: {e}")
            await self.verify_connection()
            await self.in_memory.save_conversation(session_id, conversation_doc)
            return False
    
    async def update_conversation(
        self,
        session_id: str,
        new_messages: List[Dict[str, Any]],
        intelligence: Dict[str, Any]
    ) -> bool:
        """
        Update conversation with new messages and extracted intelligence.
        Uses MongoDB's $push and $addToSet operators for atomic updates.
        """
        if self._use_in_memory:
            await self.in_memory.update_conversation(session_id, new_messages, intelligence)
            return True
        
        try:
            # Check if conversation exists
            existing = await self.get_conversation(session_id)
            if not existing:
                await self.save_conversation(session_id, {})
            
            # Build update operations
            update_ops = {
                "$push": {"messages": {"$each": new_messages}},
                "$inc": {"messageCount": len(new_messages)},
                "$set": {"updatedAt": datetime.utcnow()}
            }
            
            # Use $addToSet for unique array updates on intelligence
            intel_update = {}
            for key in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers"]:
                if key in intelligence and intelligence[key]:
                    intel_update[f"intelligence.{key}"] = {"$each": intelligence[key]}
            
            if intel_update:
                update_ops["$addToSet"] = intel_update
            
            # Update agentNotes separately (overwrite, not addToSet)
            if intelligence.get("agentNotes"):
                update_ops["$set"]["intelligence.agentNotes"] = intelligence["agentNotes"]
            
            # Update suspicious keywords with $addToSet
            if intelligence.get("suspiciousKeywords"):
                update_ops["$addToSet"] = update_ops.get("$addToSet", {})
                update_ops["$addToSet"]["intelligence.suspiciousKeywords"] = {
                    "$each": intelligence["suspiciousKeywords"]
                }
            
            result = await self.db.conversations.update_one(
                {"sessionId": session_id},
                update_ops,
                upsert=True
            )
            return result.modified_count > 0 or result.upserted_id is not None
            
        except Exception as e:
            logger.error(f"Error updating conversation: {e}")
            await self.verify_connection()
            await self.in_memory.update_conversation(session_id, new_messages, intelligence)
            return False
    
    async def get_all_intelligence(self) -> List[Dict[str, Any]]:
        """Retrieve all extracted intelligence (for analytics/reporting)."""
        if self._use_in_memory:
            return await self.in_memory.get_all_intelligence()
        
        try:
            cursor = self.db.conversations.find(
                {},
                {
                    "sessionId": 1,
                    "intelligence": 1,
                    "messageCount": 1,
                    "createdAt": 1
                }
            )
            results = []
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except Exception as e:
            logger.error(f"Error fetching all intelligence: {e}")
            await self.verify_connection()
            return await self.in_memory.get_all_intelligence()
    
    async def close(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")


# Global database manager instance
db_manager = DatabaseManager()
