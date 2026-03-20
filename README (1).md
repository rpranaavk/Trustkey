# TrustKey — AI-Powered Identity Verification Backend

TrustKey is a backend API that verifies whether a person is who they claim to be using facial recognition, detects identity-based threats such as deepfakes and impersonation, and provides a real-time security dashboard for monitoring user identity risk.

---

## The Problem

As AI-generated deepfakes, voice clones, and impersonation attacks become increasingly sophisticated, traditional identity verification methods are no longer sufficient. TrustKey addresses this by combining facial recognition with behavioral threat analysis to provide a robust identity firewall.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend Framework | FastAPI (async) |
| Database | MongoDB (Motor async driver) |
| Facial Recognition | DeepFace (Facenet model, MTCNN detector) |
| Data Validation | Pydantic |
| Environment Management | Python-dotenv |

---

## Core Features

### Identity Verification
- Upload a reference face profile for a user
- Submit a verification image to confirm identity
- Returns a confidence score using cosine similarity on face embeddings
- Stores all verification records in MongoDB for audit trails

### Threat Detection & Simulation
- Detects and logs four threat types: deepfake, voice clone, impersonation, data misuse
- Each threat includes severity level (low / medium / high / critical) and confidence score
- Threat simulation workflows for testing system robustness under adversarial conditions

### Security Dashboard
- Aggregates user profile, threat history, and verification records
- Calculates a real-time threat score based on severity weighting
- Returns protection status: `active` or `high_risk`

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/users` | Create a new user profile |
| GET | `/api/users/{user_id}` | Retrieve a user profile |
| POST | `/api/users/{user_id}/face-profile` | Upload and analyze a face image |
| POST | `/api/verify-identity` | Compare two images for identity verification |
| GET | `/api/users/{user_id}/threats` | Get threat alerts for a user |
| GET | `/api/users/{user_id}/dashboard` | Get full security dashboard |
| POST | `/api/users/{user_id}/threats/{threat_id}/takedown` | Initiate a threat takedown request |
| GET | `/api/analyze-image` | Analyze any image for face detection |

---

## How Face Verification Works

1. User registers and uploads a reference image via `/face-profile`
2. DeepFace analyzes the image using the **Facenet** model and **MTCNN** detector
3. On verification, the system compares the reference image against a new image
4. Cosine distance between face embeddings determines authenticity
5. A confidence score and verified boolean are returned and stored

---

## Project Structure

```
trustkey/
├── server.py          # Main FastAPI application — all routes, models, services
├── .env               # Environment variables (MONGO_URL, DB_NAME)
├── .gitignore
└── README.md
```

---

## Setup & Installation

### Prerequisites
- Python 3.9+
- MongoDB instance (local or cloud)

### Installation

```bash
# Clone the repository
git clone https://github.com/rpranaavk/trustkey
cd trustkey

# Install dependencies
pip install fastapi motor deepface python-dotenv pydantic uvicorn python-multipart

# Configure environment
cp .env.example .env
# Add your MONGO_URL and DB_NAME to .env

# Run the server
uvicorn server:app --reload
```

### API Documentation

Once running, visit `http://localhost:8000/docs` for the interactive Swagger UI.

---

## Roadmap

- [ ] React frontend dashboard (in progress)
- [ ] Real threat intelligence API integrations
- [ ] API key authentication
- [ ] Docker production deployment
- [ ] Rate limiting and request logging
- [ ] Tighten CORS for production environments

---

## Author

**Pranaav Ramesh Kumar**  
B.S. Cybersecurity — University of South Florida  
B.S. Data Science — IIT Madras  
[LinkedIn](https://linkedin.com/in/pranaav) | [GitHub](https://github.com/rpranaavk)
