import jwt from 'jsonwebtoken'
import asyncHandler from 'express-async-handler'
import User from '../models/userModel.js'

const protect = asyncHandler(async (req, res, next) => {
  let token

  // Check if the Authorization header exists and starts with "Bearer"
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1] // Extract token from "Bearer <token>"

      if (!token) {
        return res.status(401).json({ message: 'No token provided' })
      }

      // Verify the token using JWT secret
      const decoded = jwt.verify(token, process.env.JWT_SECRET)

      // Find user by ID from the token payload and exclude the password
      req.user = await User.findById(decoded.id).select('-password')

      if (!req.user) {
        return res.status(401).json({ message: 'User not found' })
      }

      next() // Token is valid and user is found, proceed to the next middleware
    } catch (error) {
      console.error('JWT Error:', error.message)
      res.status(401).json({ message: 'Not authorized, token failed' })
    }
  } else {
    return res.status(401).json({ message: 'Authorization token is missing or malformed' })
  }
})

// Admin role check middleware
const admin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next() // User is admin, proceed
  } else {
    res.status(401).json({ message: 'Not authorized as an admin' })
  }
}

// Admin or Seller role check middleware
const admin_seller = (req, res, next) => {
  if (req.user && req.user.isAdminSeller) {
    next() // User is admin seller, proceed
  } else {
    res.status(401).json({ message: 'Not authorized as an admin seller' })
  }
}

// Admin or Seller role check middleware
const admin_or_seller = (req, res, next) => {
  if (req.user && (req.user.isAdmin || req.user.isAdminSeller)) {
    next() // User is admin or admin seller, proceed
  } else {
    res.status(401).json({ message: 'Not authorized as an admin or admin seller' })
  }
}

export { protect, admin, admin_seller, admin_or_seller }
