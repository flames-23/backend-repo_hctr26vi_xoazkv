"""
Database Schemas for Boutique Clothing SaaS

Each Pydantic model corresponds to a MongoDB collection (lowercased name).
Indices should be added by the admin process on frequently queried fields.
"""
from __future__ import annotations
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Literal
from datetime import datetime

Size = Literal['L','XL','XXL']
SkinTone = Literal['fair','medium','dark']

class User(BaseModel):
    email: EmailStr
    password_hash: str
    size: Optional[Size] = None
    skinTone: Optional[SkinTone] = None
    savedCombos: List[str] = []
    createdAt: Optional[datetime] = None

class ProductImage(BaseModel):
    url: str
    alt: str
    width: Optional[int] = None
    height: Optional[int] = None
    format: Optional[str] = None  # png, jpg, webp

class Product(BaseModel):
    sku: str
    title: str
    description: Optional[str] = None
    price: int = Field(..., ge=0, description='Price in cents')
    inventory: int = Field(..., ge=0)
    images: List[ProductImage] = []
    category: str
    sizes: List[Size]
    skinTones: List[SkinTone]
    tags: List[str] = []
    comboCode: Optional[str] = None
    metadata: dict = {}

class Combo(BaseModel):
    title: str
    image: Optional[str] = None
    productIds: List[str]
    price: Optional[int] = None
    tags: List[str] = []
    createdBy: Optional[str] = None

class CartItem(BaseModel):
    productId: str
    qty: int
    price: int

class CartCombo(BaseModel):
    comboId: str
    qty: int

class Cart(BaseModel):
    userId: Optional[str] = None
    items: List[CartItem] = []
    combos: List[CartCombo] = []
    totals: dict = {}
