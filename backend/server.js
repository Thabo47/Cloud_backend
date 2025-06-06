const express = require("express")
const cors = require("cors")
const multer = require("multer")
const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require("@google/generative-ai")
const rateLimit = require("express-rate-limit")
const dotenv = require("dotenv")
const fs = require("fs").promises
const path = require("path")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const bodyParser = require("body-parser")

dotenv.config()
const app = express()
const PORT = process.env.PORT || 5000

// Enhanced CORS Configuration for Render + Vercel
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true)

    // Define allowed origins
    const allowedOrigins = [
      "http://localhost:3000",
      "http://localhost:5173",
      "http://localhost:3001",
      "http://127.0.0.1:3000",
      "https://iwb-public-frontend.vercel.app",
      // Add your custom domain here
      process.env.FRONTEND_URL,
      // Allow all Vercel preview deployments
      /^https:\/\/.*\.vercel\.app$/,
      // Allow all Vercel production deployments
      /^https:\/\/iwb-public-frontend.*\.vercel\.app$/,
    ].filter(Boolean) // Remove undefined values

    // Check if origin matches any allowed pattern
    const isAllowed = allowedOrigins.some((allowedOrigin) => {
      if (typeof allowedOrigin === "string") {
        return origin === allowedOrigin
      }
      if (allowedOrigin instanceof RegExp) {
        return allowedOrigin.test(origin)
      }
      return false
    })

    if (isAllowed) {
      callback(null, true)
    } else {
      console.warn(`CORS blocked origin: ${origin}`)
      callback(new Error("Not allowed by CORS"))
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
    "Cache-Control",
    "X-Access-Token",
  ],
  credentials: true,
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 200,
}

// Apply CORS middleware
app.use(cors(corsOptions))

// Security headers middleware
app.use((req, res, next) => {
  res.header("X-Content-Type-Options", "nosniff")
  res.header("X-Frame-Options", "DENY")
  res.header("X-XSS-Protection", "1; mode=block")
  res.header("Referrer-Policy", "strict-origin-when-cross-origin")

  // Add request ID for tracking
  req.requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  res.header("X-Request-ID", req.requestId)

  next()
})

// Body parsing middleware
app.use(express.json({ limit: "10mb" }))
app.use(express.urlencoded({ extended: true, limit: "10mb" }))
app.use(bodyParser.json())

// Enhanced logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString()
  const origin = req.headers.origin || "no-origin"
  console.log(`${timestamp} - ${req.method} ${req.path} - Origin: ${origin} - ID: ${req.requestId}`)

  // Log CORS preflight requests
  if (req.method === "OPTIONS") {
    console.log(`CORS Preflight: ${req.method} ${req.path} from ${origin}`)
  }

  next()
})

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/techstore", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err)
    process.exit(1)
  })

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, default: "" },
  email: {
    type: String,
    required: true,
    unique: true,
    match: [/^\S+@\S+\.\S+$/, "Please use a valid email address"],
  },
  password: {
    type: String,
    required: true,
    minlength: [8, "Password must be at least 8 characters"],
  },
  role: {
    type: String,
    required: true,
    enum: ["Client", "Developer", "Partner", "Finance", "Sales", "Investor"],
  },
  lastLogin: { type: Date },
  totalSpent: { type: Number, default: 0 },
  orderCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
})

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next()
  this.password = await bcrypt.hash(this.password, 10)
  next()
})

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password)
}

const User = mongoose.model("User", userSchema)

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  cost: { type: Number, required: true, min: 0 },
  category: {
    type: String,
    required: true,
    enum: ["CPU", "GPU", "RAM", "Motherboard", "Storage", "Peripherals", "Other"],
  },
  stock: { type: Number, required: true, min: 0 },
  minStock: { type: Number, required: true, min: 0 },
  imageUrl: { type: String, default: "" },
  isActive: { type: Boolean, default: true },
  viewCount: { type: Number, default: 0 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

const Product = mongoose.model("Product", productSchema)

// Cart Schema
const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
      quantity: { type: Number, required: true, min: 1 },
      addedAt: { type: Date, default: Date.now },
    },
  ],
  updatedAt: { type: Date, default: Date.now },
})

const Cart = mongoose.model("Cart", cartSchema)

// Order Schema
const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
      quantity: { type: Number, required: true, min: 1 },
      price: { type: Number, required: true },
    },
  ],
  totalAmount: { type: Number, required: true },
  shippingAddress: { type: String, required: true },
  paymentMethod: { type: String, required: true },
  status: {
    type: String,
    default: "Pending",
    enum: ["Pending", "Processing", "Shipped", "Delivered", "Cancelled"],
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

const Order = mongoose.model("Order", orderSchema)

// Sales Schema (for tracking individual sales)
const saleSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, required: true, min: 1 },
  price: { type: Number, required: true, min: 0 },
  total: { type: Number, required: true, min: 0 },
  soldBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  customer: {
    name: { type: String, required: true },
    email: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  order: { type: mongoose.Schema.Types.ObjectId, ref: "Order" },
  date: { type: Date, default: Date.now },
})

const Sale = mongoose.model("Sale", saleSchema)

// Query Schema
const querySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  customer: {
    name: { type: String, required: true },
    email: { type: String, required: true },
  },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  response: { type: String, default: "" },
  respondedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  status: {
    type: String,
    default: "Open",
    enum: ["Open", "In Progress", "Resolved"],
  },
  priority: {
    type: String,
    default: "Medium",
    enum: ["Low", "Medium", "High", "Urgent"],
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

const Query = mongoose.model("Query", querySchema)

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]

  if (!token) {
    return res.status(401).json({ message: "Authentication required" })
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "your-secret-key")
    req.user = decoded
    next()
  } catch (error) {
    res.status(401).json({ message: "Invalid token" })
  }
}

// Authorization Middleware
const authorizeSales = (req, res, next) => {
  if (req.user.role !== "Sales" && req.user.role !== "Admin") {
    return res.status(403).json({ message: "Unauthorized access" })
  }
  next()
}

// Rate limiting - more generous limits
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
})

// File upload configuration
const storage = multer.memoryStorage()
const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true)
    } else {
      cb(new Error("Only image files are allowed"))
    }
  },
})

// Gemini AI configuration
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
const modelName = "gemini-1.5-flash"

const safetySettings = [
  {
    category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
    threshold: HarmBlockThreshold.BLOCK_ONLY_HIGH,
  },
  {
    category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HARASSMENT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
]

const generationConfig = {
  temperature: 0.7,
  topK: 40,
  topP: 0.95,
  maxOutputTokens: 2048,
}

// Apply CORS tracking middleware
app.use(corsHandler.trackCorsRequest)

// Add CORS information routes
app.use("/api", corsRoutes)

// Declare chatSessions and chatHistory variables
const chatSessions = new Map()
const chatHistory = new Map()

// Helper function to get or create chat session
function getOrCreateSession(sessionId) {
  if (!chatSessions.has(sessionId)) {
    chatSessions.set(sessionId, {
      id: sessionId,
      createdAt: new Date(),
      lastActivity: new Date(),
      messageCount: 0,
    })
    chatHistory.set(sessionId, [])
  }
  return chatSessions.get(sessionId)
}

// Helper function to save message to history
function saveMessageToHistory(sessionId, message) {
  const history = chatHistory.get(sessionId) || []
  history.push({
    ...message,
    id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
  })
  chatHistory.set(sessionId, history)

  // Update session activity
  const session = chatSessions.get(sessionId)
  if (session) {
    session.lastActivity = new Date()
    session.messageCount = history.length
  }
}

// Main chat endpoint - FIXED VERSION
app.post("/chat", async (req, res) => {
  try {
    const { message, sessionId = "default", image, context } = req.body

    if (!message && !image) {
      return res.status(400).json({ error: "Message or image is required" })
    }

    console.log("Processing chat request:", {
      hasMessage: !!message,
      hasImage: !!image,
      sessionId,
    })

    // Get or create session
    const session = getOrCreateSession(sessionId)

    // Get chat history for context
    const history = chatHistory.get(sessionId) || []

    // Initialize Gemini model
    const model = genAI.getGenerativeModel({
      model: modelName,
      safetySettings,
      generationConfig,
    })

    // Build conversation context
    let contextPrompt = ""
    if (history.length > 0) {
      const recentHistory = history.slice(-6) // Last 6 messages for context
      contextPrompt =
        "Previous conversation context:\n" +
        recentHistory
          .filter((msg) => msg.content) // Only include messages with content
          .map((msg) => `${msg.type === "user" ? "User" : "Assistant"}: ${msg.content}`)
          .join("\n") +
        "\n\nCurrent message:\n"
    }

    // Prepare content parts for Gemini API - CORRECTED FORMAT
    const parts = []

    // Add text content
    if (message && message.trim()) {
      const fullPrompt = contextPrompt + message.trim()
      parts.push({ text: fullPrompt })
    } else if (image && !message) {
      // If only image, add a default prompt
      parts.push({ text: "Please analyze this image and describe what you see in detail." })
    }

    // Add image if provided
    if (image) {
      try {
        // Handle base64 image - remove data URL prefix if present
        let imageData = image
        if (image.includes("base64,")) {
          imageData = image.split("base64,")[1]
        } else if (image.includes(",")) {
          imageData = image.split(",")[1]
        }

        parts.push({
          inlineData: {
            mimeType: "image/jpeg", // Default to JPEG, could be made dynamic
            data: imageData,
          },
        })

        console.log("Added image to request")
      } catch (imageError) {
        console.error("Error processing image:", imageError)
        return res.status(400).json({ error: "Invalid image format" })
      }
    }

    console.log("Sending request to Gemini with parts:", parts.length)

    // Save user message to history
    if (message && message.trim()) {
      saveMessageToHistory(sessionId, {
        type: "user",
        content: message.trim(),
        hasImage: !!image,
      })
    }

    // Generate response using CORRECT API format
    const result = await model.generateContent({
      contents: [{ parts }],
    })

    const response = await result.response
    const botReply = response.text()

    console.log("Received response from Gemini")

    // Save bot response to history
    saveMessageToHistory(sessionId, {
      type: "bot",
      content: botReply,
    })

    // Send response
    res.json({
      reply: botReply,
      sessionId,
      messageCount: session.messageCount,
      safety: response.candidates?.[0]?.safetyRatings,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Chat Error:", error)

    let errorMessage = "I'm sorry, I encountered an error processing your request."
    let statusCode = 500

    if (error.message.includes("API key") || error.message.includes("PERMISSION_DENIED")) {
      errorMessage = "API configuration error. Please check the API key."
      statusCode = 503
    } else if (error.message.includes("quota") || error.message.includes("RESOURCE_EXHAUSTED")) {
      errorMessage = "Service temporarily unavailable due to high demand."
      statusCode = 503
    } else if (error.message.includes("safety") || error.message.includes("SAFETY")) {
      errorMessage = "I can't respond to that type of content. Please try a different message."
      statusCode = 400
    } else if (error.message.includes("Invalid JSON") || error.status === 400) {
      errorMessage = "Invalid request format. Please try again."
      statusCode = 400
    }

    res.status(statusCode).json({
      error: errorMessage,
      details: process.env.NODE_ENV === "development" ? error.message : undefined,
      timestamp: new Date().toISOString(),
    })
  }
})

// Get chat history
app.get("/chat/history/:sessionId", (req, res) => {
  try {
    const { sessionId } = req.params
    const { limit = 50, offset = 0 } = req.query

    const history = chatHistory.get(sessionId) || []
    const session = chatSessions.get(sessionId)

    const paginatedHistory = history.slice(Number.parseInt(offset)).slice(0, Number.parseInt(limit))

    res.json({
      history: paginatedHistory,
      total: history.length,
      session: session || null,
      hasMore: history.length > Number.parseInt(offset) + Number.parseInt(limit),
    })
  } catch (error) {
    console.error("History Error:", error)
    res.status(500).json({ error: "Failed to retrieve chat history" })
  }
})

// Clear chat history
app.delete("/chat/history/:sessionId", (req, res) => {
  try {
    const { sessionId } = req.params

    chatHistory.delete(sessionId)
    chatSessions.delete(sessionId)

    res.json({
      message: "Chat history cleared successfully",
      sessionId,
    })
  } catch (error) {
    console.error("Clear History Error:", error)
    res.status(500).json({ error: "Failed to clear chat history" })
  }
})

// Get all active sessions
app.get("/chat/sessions", (req, res) => {
  try {
    const sessions = Array.from(chatSessions.values()).map((session) => ({
      ...session,
      messageCount: chatHistory.get(session.id)?.length || 0,
    }))

    res.json({ sessions })
  } catch (error) {
    console.error("Sessions Error:", error)
    res.status(500).json({ error: "Failed to retrieve sessions" })
  }
})

// Image analysis endpoint - FIXED VERSION
app.post("/analyze-image", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image file provided" })
    }

    const { prompt = "Analyze this image and describe what you see in detail." } = req.body

    const model = genAI.getGenerativeModel({
      model: modelName,
      safetySettings,
      generationConfig,
    })

    const imageData = req.file.buffer.toString("base64")

    // Use correct API format
    const result = await model.generateContent({
      contents: [
        {
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType: req.file.mimetype,
                data: imageData,
              },
            },
          ],
        },
      ],
    })

    const response = await result.response

    res.json({
      analysis: response.text(),
      imageInfo: {
        size: req.file.size,
        type: req.file.mimetype,
        originalName: req.file.originalname,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Image Analysis Error:", error)
    res.status(500).json({
      error: "Failed to analyze image",
      details: process.env.NODE_ENV === "development" ? error.message : undefined,
    })
  }
})

// Text generation endpoint - FIXED VERSION
app.post("/generate-text", async (req, res) => {
  try {
    const { prompt, temperature = 0.7, maxTokens = 1000 } = req.body

    if (!prompt) {
      return res.status(400).json({ error: "Prompt is required" })
    }

    const model = genAI.getGenerativeModel({
      model: modelName,
      safetySettings,
      generationConfig: {
        ...generationConfig,
        temperature: Math.max(0, Math.min(1, temperature)),
        maxOutputTokens: Math.max(1, Math.min(2048, maxTokens)),
      },
    })

    // Use correct API format
    const result = await model.generateContent({
      contents: [
        {
          parts: [{ text: prompt }],
        },
      ],
    })

    const response = await result.response

    res.json({
      text: response.text(),
      prompt,
      config: {
        temperature,
        maxTokens,
        model: modelName,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Text Generation Error:", error)
    res.status(500).json({
      error: "Failed to generate text",
      details: process.env.NODE_ENV === "development" ? error.message : undefined,
    })
  }
})

// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    service: "Tech Store API",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    cors: {
      enabled: true,
      allowedOrigins: "Dynamic based on environment",
    },
  })
})

// CORS test endpoint
app.get("/api/cors/test", (req, res) => {
  res.json({
    message: "CORS is working correctly!",
    origin: req.headers.origin || "no-origin",
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
  })
})

// Auth Routes
app.post("/api/register", async (req, res) => {
  try {
    const { firstName, lastName, email, password, role } = req.body

    // Validation
    if (!firstName || !email || !password || !role) {
      return res.status(400).json({ message: "Missing required fields" })
    }

    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" })
    }

    const newUser = new User({ firstName, lastName, email, password, role })
    await newUser.save()

    // Create empty cart for new user
    if (role === "Client") {
      const newCart = new Cart({ user: newUser._id, items: [] })
      await newCart.save()
    }

    const token = jwt.sign(
      {
        userId: newUser._id,
        role: newUser.role,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
      },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: process.env.JWT_EXPIRES_IN || "1d" },
    )

    res.status(201).json({
      token,
      userId: newUser._id,
      role: newUser.role,
      user: {
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
      },
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ message: "Registration failed", error: error.message })
  }
})

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, role } = req.body

    // Validation
    if (!email || !password || !role) {
      return res.status(400).json({ message: "Missing required fields" })
    }

    const user = await User.findOne({ email })
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    const isMatch = await user.comparePassword(password)
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    if (user.role !== role) {
      return res.status(403).json({ message: "Access forbidden for this role" })
    }

    // Update last login
    user.lastLogin = new Date()
    await user.save()

    const token = jwt.sign(
      { userId: user._id, role: user.role, firstName: user.firstName, lastName: user.lastName, email: user.email },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: process.env.JWT_EXPIRES_IN || "1d" },
    )

    res.json({
      token,
      userId: user._id,
      role: user.role,
      user: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ message: "Login failed", error: error.message })
  }
})

// Product Management Routes
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find({ isActive: true }).populate("createdBy", "firstName lastName")
    res.json(products)
  } catch (error) {
    console.error("Fetch products error:", error)
    res.status(500).json({ message: "Failed to fetch products", error: error.message })
  }
})

app.post("/api/products", authenticate, authorizeSales, async (req, res) => {
  try {
    const { name, description, price, cost, category, stock, minStock, imageUrl } = req.body

    // Validation
    if (
      !name ||
      !description ||
      price === undefined ||
      cost === undefined ||
      !category ||
      stock === undefined ||
      minStock === undefined
    ) {
      return res.status(400).json({ message: "Missing required product fields" })
    }

    const product = new Product({
      name,
      description,
      price,
      cost,
      category,
      stock,
      minStock,
      imageUrl,
      createdBy: req.user.userId,
    })

    await product.save()
    res.status(201).json(product)
  } catch (error) {
    console.error("Create product error:", error)
    res.status(500).json({ message: "Failed to create product", error: error.message })
  }
})

app.put("/api/products/:id", authenticate, authorizeSales, async (req, res) => {
  try {
    const { name, description, price, cost, category, stock, minStock, imageUrl } = req.body

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      {
        name,
        description,
        price,
        cost,
        category,
        stock,
        minStock,
        imageUrl,
        updatedAt: Date.now(),
      },
      { new: true },
    )

    if (!product) {
      return res.status(404).json({ message: "Product not found" })
    }

    res.json(product)
  } catch (error) {
    console.error("Update product error:", error)
    res.status(500).json({ message: "Failed to update product", error: error.message })
  }
})

app.delete("/api/products/:id", authenticate, authorizeSales, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(req.params.id, { isActive: false }, { new: true })

    if (!product) {
      return res.status(404).json({ message: "Product not found" })
    }

    res.json({ message: "Product deleted successfully" })
  } catch (error) {
    console.error("Delete product error:", error)
    res.status(500).json({ message: "Failed to delete product", error: error.message })
  }
})

// Cart Routes
app.get("/api/cart", authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.userId }).populate("items.product")

    if (!cart) {
      const newCart = new Cart({ user: req.user.userId, items: [] })
      await newCart.save()
      return res.json(newCart)
    }

    res.json(cart)
  } catch (error) {
    console.error("Fetch cart error:", error)
    res.status(500).json({ message: "Failed to fetch cart", error: error.message })
  }
})

app.post("/api/cart", authenticate, async (req, res) => {
  try {
    const { productId, quantity } = req.body

    if (!productId || !quantity) {
      return res.status(400).json({ message: "Product ID and quantity are required" })
    }

    const product = await Product.findById(productId)
    if (!product || !product.isActive) {
      return res.status(404).json({ message: "Product not found" })
    }

    if (product.stock < quantity) {
      return res.status(400).json({ message: "Insufficient stock" })
    }

    let cart = await Cart.findOne({ user: req.user.userId })
    if (!cart) {
      cart = new Cart({ user: req.user.userId, items: [] })
    }

    const existingItem = cart.items.find((item) => item.product.toString() === productId)

    if (existingItem) {
      existingItem.quantity += quantity
    } else {
      cart.items.push({ product: productId, quantity })
    }

    cart.updatedAt = Date.now()
    await cart.save()

    const populatedCart = await Cart.findById(cart._id).populate("items.product")
    res.json(populatedCart)
  } catch (error) {
    console.error("Add to cart error:", error)
    res.status(500).json({ message: "Failed to add to cart", error: error.message })
  }
})

app.put("/api/cart/:itemId", authenticate, async (req, res) => {
  try {
    const { quantity } = req.body

    if (!quantity || quantity < 1) {
      return res.status(400).json({ message: "Valid quantity is required" })
    }

    const cart = await Cart.findOne({ user: req.user.userId })
    if (!cart) {
      return res.status(404).json({ message: "Cart not found" })
    }

    const item = cart.items.id(req.params.itemId)
    if (!item) {
      return res.status(404).json({ message: "Item not found in cart" })
    }

    item.quantity = quantity
    cart.updatedAt = Date.now()
    await cart.save()

    const populatedCart = await Cart.findById(cart._id).populate("items.product")
    res.json(populatedCart)
  } catch (error) {
    console.error("Update cart error:", error)
    res.status(500).json({ message: "Failed to update cart", error: error.message })
  }
})

app.delete("/api/cart/:itemId", authenticate, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user.userId })
    if (!cart) {
      return res.status(404).json({ message: "Cart not found" })
    }

    const item = cart.items.id(req.params.itemId)
    if (!item) {
      return res.status(404).json({ message: "Item not found in cart" })
    }

    cart.items.pull(req.params.itemId)
    cart.updatedAt = Date.now()
    await cart.save()

    const populatedCart = await Cart.findById(cart._id).populate("items.product")
    res.json(populatedCart)
  } catch (error) {
    console.error("Remove from cart error:", error)
    res.status(500).json({ message: "Failed to remove item", error: error.message })
  }
})

// Order Routes
app.post("/api/orders", authenticate, async (req, res) => {
  try {
    const { shippingAddress, paymentMethod } = req.body

    if (!shippingAddress || !paymentMethod) {
      return res.status(400).json({ message: "Shipping address and payment method are required" })
    }

    const cart = await Cart.findOne({ user: req.user.userId }).populate("items.product")
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ message: "Cart is empty" })
    }

    // Check stock availability
    for (const item of cart.items) {
      if (item.product.stock < item.quantity) {
        return res.status(400).json({
          message: `Insufficient stock for ${item.product.name}`,
        })
      }
    }

    // Calculate total
    const totalAmount = cart.items.reduce((total, item) => {
      return total + item.product.price * item.quantity
    }, 0)

    // Create order
    const order = new Order({
      user: req.user.userId,
      items: cart.items.map((item) => ({
        product: item.product._id,
        quantity: item.quantity,
        price: item.product.price,
      })),
      totalAmount,
      shippingAddress,
      paymentMethod,
    })

    await order.save()

    // Update product stock and create sales records
    for (const item of cart.items) {
      await Product.findByIdAndUpdate(item.product._id, {
        $inc: { stock: -item.quantity },
      })

      // Create sale record
      const sale = new Sale({
        product: item.product._id,
        quantity: item.quantity,
        price: item.product.price,
        total: item.product.price * item.quantity,
        customer: {
          name: `${req.user.firstName} ${req.user.lastName}`,
          email: req.user.email,
          userId: req.user.userId,
        },
        order: order._id,
      })

      await sale.save()
    }

    // Update user stats
    await User.findByIdAndUpdate(req.user.userId, {
      $inc: {
        totalSpent: totalAmount,
        orderCount: 1,
      },
    })

    // Clear cart
    cart.items = []
    await cart.save()

    const populatedOrder = await Order.findById(order._id).populate("items.product")
    res.status(201).json(populatedOrder)
  } catch (error) {
    console.error("Create order error:", error)
    res.status(500).json({ message: "Failed to place order", error: error.message })
  }
})

app.get("/api/orders", authenticate, async (req, res) => {
  try {
    const query = {}

    if (req.user.role === "Client") {
      query.user = req.user.userId
    }

    const orders = await Order.find(query)
      .populate("items.product")
      .populate("user", "firstName lastName email")
      .sort({ createdAt: -1 })

    res.json(orders)
  } catch (error) {
    console.error("Fetch orders error:", error)
    res.status(500).json({ message: "Failed to fetch orders", error: error.message })
  }
})

// Sales Routes
app.get("/api/sales", authenticate, async (req, res) => {
  try {
    const sales = await Sale.find()
      .populate("product", "name price category")
      .populate("customer.userId", "firstName lastName email")
      .sort({ date: -1 })

    res.json(sales)
  } catch (error) {
    console.error("Fetch sales error:", error)
    res.status(500).json({ message: "Failed to fetch sales", error: error.message })
  }
})

// Query Routes
app.post("/api/queries", authenticate, async (req, res) => {
  try {
    const { subject, message } = req.body

    if (!subject || !message) {
      return res.status(400).json({ message: "Subject and message are required" })
    }

    const user = await User.findById(req.user.userId)

    const query = new Query({
      user: req.user.userId,
      customer: {
        name: `${user.firstName} ${user.lastName}`,
        email: user.email,
      },
      subject,
      message,
    })

    await query.save()
    res.status(201).json(query)
  } catch (error) {
    console.error("Create query error:", error)
    res.status(500).json({ message: "Failed to create query", error: error.message })
  }
})

app.get("/api/queries", authenticate, async (req, res) => {
  try {
    const query = {}

    if (req.user.role === "Client") {
      query.user = req.user.userId
    }

    const queries = await Query.find(query).populate("user", "firstName lastName email").sort({ createdAt: -1 })

    res.json(queries)
  } catch (error) {
    console.error("Fetch queries error:", error)
    res.status(500).json({ message: "Failed to fetch queries", error: error.message })
  }
})

app.put("/api/queries/:id/respond", authenticate, authorizeSales, async (req, res) => {
  try {
    const { response } = req.body

    if (!response) {
      return res.status(400).json({ message: "Response is required" })
    }

    const query = await Query.findByIdAndUpdate(
      req.params.id,
      {
        response,
        respondedBy: req.user.userId,
        status: "Resolved",
        updatedAt: Date.now(),
      },
      { new: true },
    )

    if (!query) {
      return res.status(404).json({ message: "Query not found" })
    }

    res.json(query)
  } catch (error) {
    console.error("Respond to query error:", error)
    res.status(500).json({ message: "Failed to respond to query", error: error.message })
  }
})

// Analytics Routes
app.get("/api/analytics/sales", authenticate, authorizeSales, async (req, res) => {
  try {
    const salesData = await Sale.aggregate([
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$date" },
          },
          totalSales: { $sum: "$total" },
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
      { $limit: 30 },
    ])

    res.json(salesData)
  } catch (error) {
    console.error("Fetch sales analytics error:", error)
    res.status(500).json({ message: "Failed to fetch sales analytics", error: error.message })
  }
})

app.get("/api/analytics/clients", authenticate, authorizeSales, async (req, res) => {
  try {
    const clientData = await User.aggregate([
      { $match: { role: "Client" } },
      {
        $project: {
          firstName: 1,
          lastName: 1,
          email: 1,
          totalSpent: 1,
          orderCount: 1,
          lastLogin: 1,
          createdAt: 1,
        },
      },
      { $sort: { totalSpent: -1 } },
    ])

    res.json(clientData)
  } catch (error) {
    console.error("Fetch client analytics error:", error)
    res.status(500).json({ message: "Failed to fetch client analytics", error: error.message })
  }
})

app.get("/api/analytics/dashboard", authenticate, authorizeSales, async (req, res) => {
  try {
    const totalClients = await User.countDocuments({ role: "Client" })
    const totalOrders = await Order.countDocuments()
    const totalRevenue = await Sale.aggregate([{ $group: { _id: null, total: { $sum: "$total" } } }])
    const activeQueries = await Query.countDocuments({ status: { $ne: "Resolved" } })

    res.json({
      totalClients,
      totalOrders,
      totalRevenue: totalRevenue[0]?.total || 0,
      activeQueries,
    })
  } catch (error) {
    console.error("Fetch dashboard analytics error:", error)
    res.status(500).json({ message: "Failed to fetch dashboard analytics", error: error.message })
  }
})

// Logs Routes
app.get("/api/logs", authenticate, async (req, res) => {
  try {
    const { filter, search, startDate, endDate, limit = 100 } = req.query

    // In a real application, you would fetch from your logging system
    // For now, we'll simulate with sample data that includes real server logs
    const sampleLogs = [
      {
        id: 1,
        timestamp: new Date().toISOString(),
        level: "error",
        message: "Database connection timeout",
        source: "database",
        details: {
          error: "ETIMEDOUT",
          host: process.env.MONGO_URI || "localhost:27017",
          database: "techstore",
          connectionAttempts: 3,
        },
        userId: null,
        requestId: `req_${Date.now()}`,
        duration: null,
      },
      {
        id: 2,
        timestamp: new Date(Date.now() - 30000).toISOString(),
        level: "info",
        message: "User login successful",
        source: "auth",
        details: {
          userId: req.user?.userId,
          email: "user@example.com",
          role: req.user?.role,
          loginMethod: "email",
        },
        userId: req.user?.userId,
        requestId: `req_${Date.now() - 1}`,
        duration: 234,
      },
      {
        id: 3,
        timestamp: new Date(Date.now() - 60000).toISOString(),
        level: "warning",
        message: "High memory usage detected",
        source: "server",
        details: {
          memoryUsage: process.memoryUsage(),
          threshold: "80%",
          pid: process.pid,
        },
        userId: null,
        requestId: null,
        duration: null,
      },
      {
        id: 4,
        timestamp: new Date(Date.now() - 90000).toISOString(),
        level: "info",
        message: "API request processed",
        source: "api",
        details: {
          method: "GET",
          endpoint: "/api/products",
          statusCode: 200,
          userAgent: req.headers["user-agent"],
        },
        userId: req.user?.userId,
        requestId: `req_${Date.now() - 2}`,
        duration: 145,
      },
      {
        id: 5,
        timestamp: new Date(Date.now() - 120000).toISOString(),
        level: "error",
        message: "Payment processing failed",
        source: "payment",
        details: {
          orderId: "ord_123456",
          amount: 299.99,
          currency: "USD",
          errorCode: "CARD_DECLINED",
        },
        userId: "507f1f77bcf86cd799439011",
        requestId: `req_${Date.now() - 3}`,
        duration: 2340,
      },
      {
        id: 6,
        timestamp: new Date(Date.now() - 150000).toISOString(),
        level: "debug",
        message: "Cache operation completed",
        source: "cache",
        details: {
          operation: "SET",
          key: "products:category:CPU",
          ttl: 3600,
          size: "2.4KB",
        },
        userId: null,
        requestId: `req_${Date.now() - 4}`,
        duration: 12,
      },
    ]

    // Apply filters
    let filteredLogs = sampleLogs

    if (filter && filter !== "all") {
      filteredLogs = filteredLogs.filter((log) => log.level === filter || log.source === filter)
    }

    if (search) {
      const searchLower = search.toLowerCase()
      filteredLogs = filteredLogs.filter(
        (log) =>
          log.message.toLowerCase().includes(searchLower) ||
          log.source.toLowerCase().includes(searchLower) ||
          JSON.stringify(log.details).toLowerCase().includes(searchLower),
      )
    }

    if (startDate) {
      filteredLogs = filteredLogs.filter((log) => new Date(log.timestamp) >= new Date(startDate))
    }

    if (endDate) {
      filteredLogs = filteredLogs.filter((log) => new Date(log.timestamp) <= new Date(endDate))
    }

    // Apply limit
    filteredLogs = filteredLogs.slice(0, Number.parseInt(limit))

    // Calculate stats
    const stats = {
      total: filteredLogs.length,
      errors: filteredLogs.filter((log) => log.level === "error").length,
      warnings: filteredLogs.filter((log) => log.level === "warning").length,
      info: filteredLogs.filter((log) => log.level === "info").length,
      debug: filteredLogs.filter((log) => log.level === "debug").length,
    }

    res.json({
      logs: filteredLogs,
      stats,
      total: sampleLogs.length,
    })
  } catch (error) {
    console.error("Fetch logs error:", error)
    res.status(500).json({
      message: "Failed to fetch logs",
      error: error.message,
      logs: [],
      stats: { total: 0, errors: 0, warnings: 0, info: 0, debug: 0 },
    })
  }
})

// Real-time log streaming endpoint
app.get("/api/logs/stream", authenticate, async (req, res) => {
  try {
    // In a real application, this would connect to your log streaming service
    // For demo purposes, we'll return recent logs
    const recentLogs = [
      {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        level: ["info", "warning", "error", "debug"][Math.floor(Math.random() * 4)],
        message: [
          "New user session started",
          "Database query executed",
          "Cache miss for key: products:featured",
          "API rate limit check passed",
          "File upload completed",
        ][Math.floor(Math.random() * 5)],
        source: ["api", "database", "auth", "cache", "server"][Math.floor(Math.random() * 5)],
        details: {
          timestamp: Date.now(),
          server: "web-01",
          environment: process.env.NODE_ENV || "development",
        },
        userId: Math.random() > 0.5 ? req.user?.userId : null,
        requestId: `req_${Date.now()}`,
        duration: Math.floor(Math.random() * 500) + 50,
      },
    ]

    res.json({ newLogs: recentLogs })
  } catch (error) {
    console.error("Stream logs error:", error)
    res.status(500).json({
      message: "Failed to stream logs",
      error: error.message,
      newLogs: [],
    })
  }
})

// System metrics endpoint for performance monitoring
app.get("/api/system/metrics", authenticate, authorizeSales, async (req, res) => {
  try {
    const metrics = {
      timestamp: new Date().toISOString(),
      server: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        pid: process.pid,
        version: process.version,
      },
      database: {
        // In a real app, you'd get actual DB metrics
        connections: Math.floor(Math.random() * 50) + 10,
        queries: Math.floor(Math.random() * 1000) + 500,
        avgResponseTime: Math.floor(Math.random() * 100) + 50,
      },
      api: {
        requestsPerMinute: Math.floor(Math.random() * 500) + 200,
        avgResponseTime: Math.floor(Math.random() * 200) + 100,
        errorRate: Math.random() * 5,
      },
    }

    res.json(metrics)
  } catch (error) {
    console.error("Fetch system metrics error:", error)
    res.status(500).json({
      message: "Failed to fetch system metrics",
      error: error.message,
    })
  }
})

// CORS error handling middleware
app.use((error, req, res, next) => {
  if (error.message === "Not allowed by CORS") {
    return res.status(403).json({
      error: "CORS Error",
      message: "Origin not allowed",
      origin: req.headers.origin || "no-origin",
      timestamp: new Date().toISOString(),
    })
  }
  next(error)
})

// Global error handling middleware
app.use((error, req, res, next) => {
  console.error("Unhandled Error:", error)
  res.status(500).json({
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? error.message : "Something went wrong",
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
  })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
  })
})

// Cleanup old sessions (run every hour)
setInterval(
  () => {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000)

    for (const [sessionId, session] of chatSessions.entries()) {
      if (session.lastActivity < oneHourAgo) {
        chatSessions.delete(sessionId)
        chatHistory.delete(sessionId)
        console.log(`Cleaned up inactive session: ${sessionId}`)
      }
    }
  },
  60 * 60 * 1000,
)

// Graceful shutdown handling
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully")
  mongoose.connection.close(() => {
    console.log("MongoDB connection closed")
    process.exit(0)
  })
})

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully")
  mongoose.connection.close(() => {
    console.log("MongoDB connection closed")
    process.exit(0)
  })
})

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`)
  console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`)
  console.log(`🔗 Health check: http://localhost:${PORT}/`)
  console.log(`🧪 CORS test: http://localhost:${PORT}/api/cors/test`)
  console.log(`📊 MongoDB: ${process.env.MONGO_URI ? "Connected" : "Local"}`)
})
