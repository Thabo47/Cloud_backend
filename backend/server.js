const express = require("express")
const cors = require("cors")
const rateLimit = require("express-rate-limit")
const dotenv = require("dotenv")
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
    ].filter(Boolean) // Remove undefined values

    // Check for Vercel preview deployments
    const isVercelPreview = origin && /^https:\/\/.*\.vercel\.app$/.test(origin)
    const isAllowedOrigin = allowedOrigins.includes(origin)

    if (isAllowedOrigin || isVercelPreview) {
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

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
})

app.use(limiter)

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

// Sales Schema
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

// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    service: "Tech Store API",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
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

    if (!firstName || !email || !password || !role) {
      return res.status(400).json({ message: "Missing required fields" })
    }

    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" })
    }

    const newUser = new User({ firstName, lastName, email, password, role })
    await newUser.save()

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

// Product Routes
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

// Order Routes
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

// Query Routes
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
    console.error("Analytics sales error:", error)
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
    console.error("Analytics clients error:", error)
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
    console.error("Analytics dashboard error:", error)
    res.status(500).json({ message: "Failed to fetch dashboard analytics", error: error.message })
  }
})

// Error handling middleware
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

// Graceful shutdown
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
