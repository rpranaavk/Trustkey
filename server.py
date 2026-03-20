from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import tempfile
import json
from dotenv import load_dotenv

# Configure logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import DeepFace for facial recognition
try:
    from deepface import DeepFace
    DEEPFACE_AVAILABLE = True
    logger.info("DeepFace imported successfully")
except ImportError as e:
    DEEPFACE_AVAILABLE = False
    logger.error(f"DeepFace not installed: {e}")
    print("DeepFace not available")

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="TrustKey API", description="AI-powered identity firewall", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Models
class UserProfile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: str
    phone: Optional[str] = None
    face_embedding: Optional[List[float]] = None
    voice_profile: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
class ThreatAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    threat_type: str  # deepfake, voice_clone, impersonation, data_misuse
    severity: str  # low, medium, high, critical
    confidence: float
    description: str
    source: str
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "active"  # active, investigating, resolved, false_positive
    
class IdentityVerification(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    verification_type: str  # face, voice, combined
    is_authentic: bool
    confidence_score: float
    details: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class CreateUserProfile(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None

# DeepFace Service Class
class FaceRecognitionService:
    def __init__(self):
        self.model_name = 'Facenet'
        self.detector_backend = 'mtcnn'
        self.distance_metric = 'cosine'
        self.threshold = 0.6
        
    async def analyze_face(self, image_data: bytes) -> Dict[str, Any]:
        """Analyze face attributes using DeepFace"""
        if not DEEPFACE_AVAILABLE:
            raise HTTPException(status_code=503, detail="DeepFace not available")
            
        try:
            # Save image to temporary file
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
                temp_file.write(image_data)
                temp_path = temp_file.name
            
            try:
                # Perform analysis
                analysis = DeepFace.analyze(
                    img_path=temp_path,
                    actions=['age', 'gender', 'emotion'],
                    detector_backend=self.detector_backend,
                    enforce_detection=False,
                    silent=True
                )
                
                # Handle both single face and multiple faces
                if isinstance(analysis, list):
                    result = analysis[0] if analysis else {}
                else:
                    result = analysis
                    
                return {
                    'faces_detected': 1 if result else 0,
                    'age': result.get('age'),
                    'gender': result.get('gender', {}),
                    'emotion': result.get('emotion', {}),
                    'dominant_emotion': result.get('dominant_emotion'),
                    'region': result.get('region', {}),
                    'face_confidence': result.get('face_confidence', 0)
                }
                
            finally:
                # Clean up temp file
                os.unlink(temp_path)
                
        except Exception as e:
            logger.error(f"Face analysis error: {e}")
            raise HTTPException(status_code=500, detail=f"Face analysis failed: {str(e)}")
    
    async def verify_face(self, image1_data: bytes, image2_data: bytes) -> Dict[str, Any]:
        """Verify if two images contain the same person"""
        if not DEEPFACE_AVAILABLE:
            raise HTTPException(status_code=503, detail="DeepFace not available")
            
        try:
            # Save both images to temporary files
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp1:
                temp1.write(image1_data)
                temp_path1 = temp1.name
                
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp2:
                temp2.write(image2_data)
                temp_path2 = temp2.name
            
            try:
                # Perform verification
                verification = DeepFace.verify(
                    img1_path=temp_path1,
                    img2_path=temp_path2,
                    model_name=self.model_name,
                    detector_backend=self.detector_backend,
                    distance_metric=self.distance_metric,
                    enforce_detection=False
                )
                
                return {
                    'verified': verification.get('verified', False),
                    'distance': verification.get('distance', 1.0),
                    'threshold': verification.get('threshold', self.threshold),
                    'model': self.model_name,
                    'confidence': max(0, 1 - verification.get('distance', 1.0))
                }
                
            finally:
                # Clean up temp files
                os.unlink(temp_path1)
                os.unlink(temp_path2)
                
        except Exception as e:
            logger.error(f"Face verification error: {e}")
            raise HTTPException(status_code=500, detail=f"Face verification failed: {str(e)}")

# Initialize face recognition service
face_service = FaceRecognitionService()

# Mock data generator for threats
def generate_mock_threats(user_id: str) -> List[ThreatAlert]:
    """Generate mock threat data for demonstration"""
    mock_threats = [
        {
            "user_id": user_id,
            "threat_type": "deepfake",
            "severity": "high",
            "confidence": 0.87,
            "description": "Deepfake video detected on social media platform",
            "source": "Twitter/X automated scan",
            "detected_at": datetime.utcnow() - timedelta(hours=2)
        },
        {
            "user_id": user_id,
            "threat_type": "impersonation",
            "severity": "medium",
            "confidence": 0.73,
            "description": "Fake LinkedIn profile using your photo",
            "source": "LinkedIn monitoring",
            "detected_at": datetime.utcnow() - timedelta(hours=6)
        },
        {
            "user_id": user_id,
            "threat_type": "voice_clone",
            "severity": "critical",
            "confidence": 0.94,
            "description": "AI voice clone detected in phone scam attempt",
            "source": "Dark web monitoring",
            "detected_at": datetime.utcnow() - timedelta(days=1)
        },
        {
            "user_id": user_id,
            "threat_type": "data_misuse",
            "severity": "medium",
            "confidence": 0.68,
            "description": "Personal writing style detected in AI training dataset",
            "source": "LLM training data analysis",
            "detected_at": datetime.utcnow() - timedelta(days=2)
        }
    ]
    
    return [ThreatAlert(**threat) for threat in mock_threats]

# API Routes
@api_router.get("/")
async def root():
    return {"message": "TrustKey API - Your Personal Identity Firewall"}

@api_router.post("/users", response_model=UserProfile)
async def create_user_profile(user_data: CreateUserProfile):
    """Create new user profile"""
    user = UserProfile(**user_data.dict())
    await db.users.insert_one(user.dict())
    return user

@api_router.get("/users/{user_id}", response_model=UserProfile)
async def get_user_profile(user_id: str):
    """Get user profile by ID"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfile(**user)

@api_router.post("/users/{user_id}/face-profile")
async def upload_face_profile(user_id: str, image: UploadFile = File(...)):
    """Upload and analyze face for user profile"""
    if not image.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    image_data = await image.read()
    
    # Analyze the face
    analysis = await face_service.analyze_face(image_data)
    
    # Update user profile with face data
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "face_analysis": analysis,
            "updated_at": datetime.utcnow()
        }}
    )
    
    return {"message": "Face profile updated", "analysis": analysis}

@api_router.post("/verify-identity")
async def verify_identity(
    user_id: str = Form(...),
    reference_image: UploadFile = File(...),
    verification_image: UploadFile = File(...)
):
    """Verify identity using face comparison"""
    if not reference_image.content_type.startswith('image/') or not verification_image.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="Both files must be images")
    
    ref_data = await reference_image.read()
    ver_data = await verification_image.read()
    
    # Perform face verification
    verification_result = await face_service.verify_face(ref_data, ver_data)
    
    # Create verification record
    verification = IdentityVerification(
        user_id=user_id,
        verification_type="face",
        is_authentic=verification_result['verified'],
        confidence_score=verification_result['confidence'],
        details=verification_result
    )
    
    await db.verifications.insert_one(verification.dict())
    
    return verification

@api_router.get("/users/{user_id}/threats", response_model=List[ThreatAlert])
async def get_user_threats(user_id: str):
    """Get threat alerts for user"""
    # For demo, return mock threats
    # In production, this would query actual threat detection systems
    threats = generate_mock_threats(user_id)
    return threats

@api_router.get("/users/{user_id}/dashboard")
async def get_user_dashboard(user_id: str):
    """Get user dashboard data"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    threats = generate_mock_threats(user_id)
    
    # Calculate threat score
    total_threats = len(threats)
    critical_threats = len([t for t in threats if t.severity == "critical"])
    high_threats = len([t for t in threats if t.severity == "high"])
    
    threat_score = min(100, (critical_threats * 25) + (high_threats * 15) + (total_threats * 5))
    
    # Recent verifications
    verifications = await db.verifications.find(
        {"user_id": user_id}
    ).sort("timestamp", -1).limit(5).to_list(5)
    
    return {
        "user": UserProfile(**user),
        "threat_score": threat_score,
        "total_threats": total_threats,
        "threats_by_severity": {
            "critical": critical_threats,
            "high": high_threats,
            "medium": len([t for t in threats if t.severity == "medium"]),
            "low": len([t for t in threats if t.severity == "low"])
        },
        "recent_threats": threats[:3],  # Last 3 threats
        "recent_verifications": [IdentityVerification(**v) for v in verifications],
        "protection_status": "active" if threat_score < 70 else "high_risk"
    }

@api_router.post("/users/{user_id}/threats/{threat_id}/takedown")
async def initiate_takedown(user_id: str, threat_id: str):
    """Initiate takedown action for a threat"""
    # This would integrate with actual takedown services in production
    return {
        "message": "Takedown request initiated",
        "threat_id": threat_id,
        "status": "pending",
        "estimated_completion": datetime.utcnow() + timedelta(hours=24)
    }

@api_router.get("/analyze-image")
async def analyze_uploaded_image(image: UploadFile = File(...)):
    """Analyze any uploaded image for face detection"""
    if not image.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    image_data = await image.read()
    analysis = await face_service.analyze_face(image_data)
    
    return {
        "filename": image.filename,
        "analysis": analysis,
        "timestamp": datetime.utcnow()
    }

# Include the router in the main app
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()