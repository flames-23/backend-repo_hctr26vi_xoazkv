import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User as UserSchema, Product as ProductSchema, Combo as ComboSchema, Cart as CartSchema

# Environment & Security
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

app = FastAPI(title="Boutique Clothing API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class RegisterPayload(BaseModel):
    email: EmailStr
    password: str

class ProfilePayload(BaseModel):
    size: Optional[str] = None
    skinTone: Optional[str] = None

# Auth utilities

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"email": email})
    if not user:
        raise credentials_exception
    return user


@app.get("/")
def root():
    return {"message": "Boutique Clothing API running"}

# Auth
@app.post("/api/auth/register", response_model=Token)
def register(payload: RegisterPayload):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(payload.password)
    doc = UserSchema(email=payload.email, password_hash=hashed, createdAt=datetime.utcnow())
    user_id = create_document("user", doc)
    token = create_access_token({"sub": payload.email})
    return Token(access_token=token)


@app.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user["email"]})
    return Token(access_token=token)


# User profile
@app.get("/api/user/profile")
def get_profile(current_user = Depends(get_current_user)):
    user = db["user"].find_one({"email": current_user["email"]}, {"password_hash": 0})
    user["id"] = str(user.pop("_id"))
    return user


@app.put("/api/user/profile")
def update_profile(payload: ProfilePayload, current_user = Depends(get_current_user)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["user"].update_one({"email": current_user["email"]}, {"$set": update})
    user = db["user"].find_one({"email": current_user["email"]}, {"password_hash": 0})
    user["id"] = str(user.pop("_id"))
    return user


# Products
@app.get("/api/products")
def list_products(size: Optional[str] = None, skinTone: Optional[str] = None, category: Optional[str] = None, q: Optional[str] = None, sort: Optional[str] = None, limit: int = 30, page: int = 1):
    query = {}
    if size:
        query["sizes"] = {"$in": [size]}
    if skinTone:
        query["skinTones"] = {"$in": [skinTone]}
    if category:
        query["category"] = category
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"tags": {"$elemMatch": {"$regex": q, "$options": "i"}}},
            {"sku": {"$regex": q, "$options": "i"}},
        ]
    sort_spec = [("_id", -1)]
    if sort == "newest":
        sort_spec = [("_id", -1)]
    elif sort == "price":
        sort_spec = [("price", 1)]
    elif sort == "trending":
        sort_spec = [("metadata.trending", -1), ("_id", -1)]

    skip = (page - 1) * limit
    cursor = db["product"].find(query).sort(sort_spec).skip(skip).limit(limit)
    results = []
    for p in cursor:
        p["id"] = str(p.pop("_id"))
        results.append(p)
    return {"items": results, "page": page, "limit": limit}


@app.get("/api/products/{pid}")
def product_detail(pid: str):
    from bson import ObjectId
    p = db["product"].find_one({"_id": ObjectId(pid)})
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    p["id"] = str(p.pop("_id"))
    # Add combo badge info
    if p.get("comboCode"):
        combo = db["combo"].find_one({"productIds": p["id"]})
        p["partOfCombo"] = True if combo else False
    return p


# Combos
@app.get("/api/combos")
def list_combos(size: Optional[str] = None, skinTone: Optional[str] = None):
    query = {}
    if size:
        query["metadata.sizes"] = {"$in": [size]}
    if skinTone:
        query["metadata.skinTones"] = {"$in": [skinTone]}
    combos = []
    for c in db["combo"].find(query).sort([("_id", -1)]).limit(30):
        c["id"] = str(c.pop("_id"))
        combos.append(c)
    return {"items": combos}


# Cart
class CartInput(BaseModel):
    productId: Optional[str] = None
    comboId: Optional[str] = None
    qty: int = 1

@app.post("/api/cart")
def add_to_cart(payload: CartInput, current_user = Depends(get_current_user)):
    cart = db["cart"].find_one({"userId": str(current_user["_id"])})
    if not cart:
        cart = {"userId": str(current_user["_id"]), "items": [], "combos": [], "totals": {}}
        db["cart"].insert_one(cart)
    updates = {}
    if payload.productId:
        p = db["product"].find_one({"_id": __import__('bson').ObjectId(payload.productId)})
        if not p:
            raise HTTPException(status_code=404, detail="Product not found")
        cart["items"].append({"productId": payload.productId, "qty": payload.qty, "price": p["price"]})
        updates["items"] = cart["items"]
    if payload.comboId:
        c = db["combo"].find_one({"_id": __import__('bson').ObjectId(payload.comboId)})
        if not c:
            raise HTTPException(status_code=404, detail="Combo not found")
        cart["combos"].append({"comboId": payload.comboId, "qty": payload.qty})
        updates["combos"] = cart["combos"]
    db["cart"].update_one({"userId": str(current_user["_id"])}, {"$set": updates})
    return {"ok": True}


# Checkout (stub or Stripe-ready)
class CheckoutInput(BaseModel):
    cartId: Optional[str] = None

@app.post("/api/checkout")
def checkout(_: CheckoutInput, current_user = Depends(get_current_user)):
    # Stubbed payment session response (replace with Stripe if desired)
    return {"paymentSessionId": f"stub_{str(current_user['_id'])}", "checkoutUrl": "https://example.com/checkout/stub"}


# Admin Import
class ImportReport(BaseModel):
    total: int
    created: int
    errors: List[str]

@app.post("/api/admin/import-csv")
async def import_csv(
    csv_file: UploadFile = File(...),
    assets_zip: Optional[UploadFile] = File(None),
    current_user = Depends(get_current_user)
):
    # Simple admin check: first registered user is admin
    first_user = db["user"].find().sort("_id", 1).limit(1)
    admin_email = None
    for u in first_user:
        admin_email = u.get("email")
    if current_user.get("email") != admin_email:
        raise HTTPException(status_code=403, detail="Admin only")

    import csv, io, zipfile
    text = (await csv_file.read()).decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))
    created = 0
    errors: List[str] = []

    # Optionally process images in zip and map file_name -> stored url (here just a stub path)
    image_map = {}
    if assets_zip is not None:
        data = await assets_zip.read()
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    image_map[os.path.basename(name)] = f"/assets/{os.path.basename(name)}"
        except Exception as e:
            errors.append(f"Zip processing failed: {str(e)}")

    for row in reader:
        # Validate filename pattern: category_size_skintone_001.png
        fname = row.get("file_name", "")
        try:
            category, size, skin, _ = os.path.splitext(fname)[0].split("_")
        except Exception:
            errors.append(f"Bad file name: {fname}")
            continue
        if size.lower() not in ["l","xl","xxl"] or skin.lower() not in ["fair","medium","dark"]:
            errors.append(f"Size/skin mismatch in file name: {fname}")
            continue
        try:
            sizes = list({row.get("size"), size.upper()})
            skinTones = list({row.get("skinTone").lower(), skin.lower()})
            price = int(row.get("price", 0))
            inventory = int(row.get("inventory", 0))
            images = [{
                "url": image_map.get(fname, f"/assets/{fname}"),
                "alt": row.get("title") or fname,
            }]
            product = {
                "sku": row.get("sku") or row.get("image_code"),
                "title": row.get("title") or os.path.splitext(fname)[0],
                "description": row.get("description") or "",
                "price": price,
                "inventory": inventory,
                "images": images,
                "category": row.get("category") or category,
                "sizes": [s for s in sizes if s],
                "skinTones": [t for t in skinTones if t],
                "tags": [t.strip() for t in (row.get("styleTags") or "").split(",") if t.strip()],
                "comboCode": row.get("comboCode") or None,
                "metadata": {"sourceFile": fname},
            }
            create_document("product", product)
            created += 1
        except Exception as e:
            errors.append(f"Row error {row.get('image_code')}: {str(e)}")

    return ImportReport(total=created + len(errors), created=created, errors=errors)


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
