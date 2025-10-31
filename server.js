import express from "express";
import mongoose from "mongoose";
import dotenv, { populate } from "dotenv";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import cloudinary from "./cloudinaryCofig.js"; // Ensure correct spelling
import multer from "multer";
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";
import admin from "firebase-admin";
import fs from "fs";
import { getAuth } from "firebase-admin/auth";
import { Readable } from "stream"; // Add this for streaming Buffers
import Challenge from "./Schema/Challenge.js";
import { startOfWeek, endOfWeek } from "date-fns";
import { Server as SocketIoServer } from "socket.io";
import http from "http";
import Messages from "./Schema/Messages.js";
import Anonymous from "./Schema/Anonymous.js";
import crypto from "crypto";
import { Resend } from "resend";
import { title } from "process";
import Token from "./Schema/Token.js";

dotenv.config();

const server = express();
const socketServer = http.createServer(server);
const port = process.env.PORT || 3000;

const serviceAccountKey = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"), // Handle newlines
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

server.use(express.json());
const allowedOrigins = [
  "http://localhost:5173", // Local development
  "https://www.campus-connect.xyz",
  "https://campus-connect.xyz", //main deployment
];

server.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g., server-to-server or Postman)
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // If your app uses cookies or auth headers
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allowed HTTP methods
    allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
  })
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

const formatDataToSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
    userId: user._id,
    following: user.following,
  };
};

const verifyJwt = (req, res, next) => {
  const autheader = req.headers["authorization"];
  const token = autheader && autheader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "No access token provided" });
  }
  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      console.log("JWT Verify Error:", err.message); // Debug log
      return res.status(403).json({ error: "Access token is invalid" });
    }
    req.user = user.id;

    next();
  });
};

const generateUsername = async (email) => {
  let username = email.split("@")[0];
  const isUsernameNotUnique = await User.exists({
    "personal_info.username": username,
  }).then((result) => result);
  isUsernameNotUnique ? (username += nanoid().substring(0, 5)) : "";
  return username;
};

//pping
server.get("/ping", (req, res) => {
  res.status(200).send("OK");
});
// Existing routes (signup, signin, google-auth) remain unchanged...
server.post("/signup", (req, res) => {
  const { fullname, email, password } = req.body;

  if (fullname.length < 3 || fullname.length > 20) {
    return res
      .status(403)
      .json({ error: "Fullname must be at least 3 letters long" });
  }
  if (!email) {
    return res.status(403).json({ error: "Email is required" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email is invalid" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 letters long with a numeric,1 lowercase and 1 uppercase letters ",
    });
  }

  bcrypt.hash(password, 10, async (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: "Error hashing password" });
    }

    let username = await generateUsername(email);

    const user = new User({
      personal_info: {
        fullname: fullname,
        email: email,
        password: hashedPassword,
        username,
      },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDataToSend(u));
      })
      .catch((err) => {
        if (err.code == 11000) {
          return res.status(500).json({ error: "Email Already exists" });
        }
        return res.status(500).json({ error: err.message });
      });
  });
});

server.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ "personal_info.email": email });

    if (!user) {
      return res.status(403).json({ error: "Email not found" });
    }

    if (user.google_auth) {
      return res.status(403).json({
        error: "Account was created with Google. Please sign in with Google.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.personal_info.password);

    if (!isMatch) {
      return res.status(403).json({ error: "Incorrect password" });
    }

    return res.status(200).json(formatDataToSend(user));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error, please try again." });
  }
});

server.post("/google-auth", async (req, res) => {
  try {
    const { access_token } = req.body;
    if (!access_token) {
      return res.status(400).json({ error: "Access token is required" });
    }

    const decodedUser = await getAuth().verifyIdToken(access_token);
    let { email, name, picture } = decodedUser;
    picture = picture.replace("s96-c", "s384-c");

    let user = await User.findOne({ "personal_info.email": email });

    if (user && !user.google_auth) {
      return res.status(403).json({
        error: "This email was signed up without Google. Use password login.",
      });
    }

    if (!user) {
      const username = await generateUsername(email);
      user = new User({
        personal_info: {
          email,
          fullname: name || email.split("@")[0],
          profile_img: picture,
          username,
        },
        google_auth: true,
      });

      await user.save();
    }

    return res.status(200).json(formatDataToSend(user));
  } catch (err) {
    console.error("Google Auth Error:", err);
    return res.status(500).json({ error: "Failed to authenticate" });
  }
});

server.post("/change-password", verifyJwt, (req, res) => {
  let { currentPassword, newPassword } = req.body;
  if (
    !passwordRegex.test(currentPassword) ||
    !passwordRegex.test(newPassword)
  ) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 letters long with a numeric,1 lowercase and 1 uppercase letters ",
    });
  }

  User.findOne({ _id: req.user })
    .then((user) => {
      if (user.google_auth) {
        return res.status(403).json({
          error:
            "you can't change the account password because you loggged in with google",
        });
      }
      bcrypt.compare(
        currentPassword,
        user.personal_info.password,
        (err, result) => {
          if (err) {
            return res.status(500).json({
              error:
                "Some error occured while changing password ,try again later",
            });
          }
          if (!result) {
            return res
              .status(403)
              .json({ error: "incorrect current password" });
          }
          bcrypt.hash(newPassword, 10, (err, hashed_password) => {
            User.findOneAndUpdate(
              { _id: req.user },
              { "personal_info.password": hashed_password }
            )
              .then((u) => {
                return res.status(200).json({ status: "password changed" });
              })
              .catch((err) => {
                return res.status(500).json({
                  error:
                    "Some error occured while changing password ,try again later",
                });
              });
          });
        }
      );
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ error: "user not found" });
    });
});

// /upload-image route (unchanged from base64 approach)
server.post("/upload-image", upload.single("image"), async (req, res) => {
  try {
    const image = req.file;
    if (!image) {
      console.log("No image file received");
      return res.status(400).json({ error: "Image is required" });
    }

    // Convert Buffer to a Readable stream for Cloudinary
    const bufferStream = new Readable();
    bufferStream.push(image.buffer);
    bufferStream.push(null); // Signal end of stream

    console.log("Uploading to Cloudinary...");
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: "user_images",
        public_id: `user_${nanoid()}`,
        transformation: [{ width: 500, height: 500, crop: "limit" }],
      },
      (error, result) => {
        if (error) {
          console.error("Cloudinary Stream Upload Error:", error);
          return res
            .status(500)
            .json({ error: "Failed to upload image", details: error.message });
        }
        console.log("Upload successful:", result.secure_url);
        res.status(200).json({
          message: "Image uploaded successfully",
          imageUrl: result.secure_url,
        });
      }
    );

    bufferStream.pipe(uploadStream);
  } catch (error) {
    console.error("Upload Error:", error.stack);
    res
      .status(500)
      .json({ error: "Failed to upload image", details: error.message });
  }
});

//get all users count
server.get("/all-users", async (req, res) => {
  try {
    const count = await User.countDocuments();
    res.status(200).json({ count });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

//get the blog
server.post("/latest-blog", (req, res) => {
  let { page } = req.body;
  let maxLimit = 30;
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname personal_info.isVerified -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title content des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ err: err.message });
    });
});
server.post("/for-you", verifyJwt, async (req, res) => {
  try {
    let userId = req.user;
    let { page = 1 } = req.body;
    let maxLimit = 30;

    let user = await User.findById(userId).select("following");
    let following = user?.following || [];

    let blogs = await Blog.find({
      draft: false,
      author: { $in: following },
    })
      .populate(
        "author",
        "personal_info.profile_img personal_info.username personal_info.fullname personal_info.isVerified -_id"
      )
      .sort({ publishedAt: -1 })
      .select(
        "blog_id title des content banner activity tags publishedAt -_id "
      )
      .skip((page - 1) * maxLimit)
      .limit(maxLimit);

    return res.status(200).json({ blogs });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: "Internal server error" });
  }
});
server.post("/all-latest-feed", verifyJwt, async (req, res) => {
  let userId = req.user;
  let user = await User.findById(userId).select("following");
  let following = user?.following || [];

  Blog.countDocuments({ draft: false, author: { $in: following } })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

server.post("/all-latest-blogs-count", (req, res) => {
  Blog.countDocuments({ draft: false })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

//trending blogs
server.get("/trending-blogs", (req, res) => {
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname personal_info.isVerified -_id"
    )
    .sort({
      "activity.total_read": -1,
      "activity.total_likes": -1,
      publishedAt: -1,
    })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .limit(20)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ err: err.message });
    });
});
server.post("/search-blogs", (req, res) => {
  let { query, tag, page, author, limit, eliminate_blog } = req.body;
  let findQuery;
  if (tag) {
    findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { author, draft: false };
  }
  let maxLimit = limit ? limit : 5;
  Blog.find(findQuery)
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname personal_info.isVerified -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des content banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ err: err.message });
    });
});
server.post("/search-blogs-count", (req, res) => {
  let { query, tag, author } = req.body;
  let findQuery;

  if (tag) {
    findQuery = { tags: tag, draft: false };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  Blog.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

//search for users
server.post("/search-user", (req, res) => {
  let { query } = req.body;
  User.find({ "personal_info.username": new RegExp(query, "i") })
    .limit(50)
    .select(
      "personal_info.fullname personal_info.profile_img personal_info.username -_id"
    )
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//search useers for messages because normal search user uses query
server.post("/search-dm", verifyJwt, (req, res) => {
  let { searchUser } = req.body;
  if (!searchUser || !searchUser.length > 1) {
    return res.status(400).json({ error: "Search query is required" });
  }
  // _id:{$ne:req.userId}
  User.find({
    _id: { $ne: req.user },
    "personal_info.username": new RegExp(searchUser, "i"),
  })
    .limit(50)
    .select(
      "personal_info.fullname personal_info.profile_img personal_info.username _id"
    )
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//get user info with id
server.post("/get-user-info", verifyJwt, (req, res) => {
  const { chatIdFromUrl } = req.body;

  if (!chatIdFromUrl) {
    return res.status(400).json({ error: "chatIdFromUrl is required" });
  }

  // Prevent fetching the current user's own info
  if (chatIdFromUrl === req.user) {
    return res.status(400).json({ error: "You cannot fetch your own info" });
  }

  User.findById(chatIdFromUrl)
    .select(
      "personal_info.fullname personal_info.profile_img personal_info.username _id"
    )
    .then((user) => {
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(200).json({ user });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//follow a user
server.post("/follows/:id", verifyJwt, async (req, res) => {
  try {
    const { id } = req.params;
    const userTomodify = await User.findById(id);
    const currentUser = await User.findById(req.user);

    if (id === req.user.toString()) {
      return res
        .status(400)
        .json({ message: "You cant Follow/Unfollow yourself" });
    }
    if (!userTomodify || !currentUser) {
      return res.status(400).json({ message: "User not found" });
    }
    const isFollowing = currentUser.following.includes(id);
    const user = await User.findById(req.user).select(
      "personal_info.fullname personal_info.username"
    );

    // 3️⃣ Get tokens of the blog author
    const tokens = await Token.find({ user: id }).select("token -_id");
    if (isFollowing) {
      //unfollow the user
      await Promise.all([
        User.findByIdAndUpdate(id, { $pull: { followers: req.user } }),
        User.findByIdAndUpdate(req.user, { $pull: { following: id } }),
      ]);

      return res.status(200).json({ following: false });
    } else {
      //follow the user
      await Promise.all([
        User.findByIdAndUpdate(id, { $addToSet: { followers: req.user } }),
        User.findByIdAndUpdate(req.user, { $addToSet: { following: id } }),
      ]);
      await Notification.create({
        type: "followed",
        notification_for: id,
        user: req.user,
        seen: false,
      });

      const tokenList = tokens.map((t) => t.token);

      if (tokenList.length > 0) {
        // 4️⃣ Build the notification message
        const message = {
          notification: {
            title: `${user.personal_info.fullname || user.personal_info.username} just followed You`,
            body: "Your just got a new Follower",
          },
          data: {
            url: process.env.VITE_CLIENT_DOMAIN + "/dashboard/notifications", // ✅ accessible on client as payload.data.link
          },
          tokens: tokenList,
        };

        // 5️⃣ Send push notification
        const response = await admin.messaging().sendEachForMulticast(message);

        console.log(
          "Push notification detailed response:",
          JSON.stringify(response, null, 2)
        );

        // 🔄 Cleanup invalid tokens
        response.responses.forEach(async (r, i) => {
          if (
            !r.success &&
            ["InvalidRegistration", "NotRegistered"].includes(r.error.code)
          ) {
            await Token.deleteOne({ token: tokenList[i] });
            console.log("Deleted invalid token:", tokenList[i]);
          }
        });
      }
      return res.status(200).json({ following: true });
    }
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: error.message });
  }
});

//get the following or followers
server.get("/:username/:type", async (req, res) => {
  try {
    const { username, type } = req.params;

    if (!["following", "followers"].includes(type)) {
      return res
        .status(400)
        .json({ message: "query should be following or followers" });
    }

    const user = await User.findOne({
      "personal_info.username": username,
    }).populate({
      select:
        "personal_info.profile_img personal_info.username personal_info.fullname personal_info.isVerified -_id",
      path: type,
    });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const list = user[type];
    if (!list) {
      return res.status(404).json({ message: "No followers" });
    }
    return res.status(200).json(list);
  } catch (error) {
    console.log(error.message);
    return res.status(500).json({ message: error.message });
  }
});

// get user for useerProfile page
// remeber you made a mistaje in twitter

server.post("/get-profile", (req, res) => {
  let { username } = req.body;
  User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then((user) => {
      return res.status(200).json(user);
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({ error: err.message });
    });
});

server.post("/update-profile-img", verifyJwt, async (req, res) => {
  try {
    const { profile_img } = req.body; // Changed from imageUrl to profile_img
    if (!profile_img) {
      console.log("No profile_img provided in request body:", req.body);
      return res.status(400).json({ error: "Profile image URL is required" });
    }

    console.log(
      "Updating profile image for user:",
      req.user,
      "with URL:",
      profile_img
    );
    const user = await User.findOneAndUpdate(
      { _id: req.user },
      { $set: { "personal_info.profile_img": profile_img } },
      { new: true, runValidators: true }
    );

    if (!user) {
      console.log("User not found for ID:", req.user);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("Updated profile image:", user.personal_info.profile_img);
    return res
      .status(200)
      .json({ profile_img: user.personal_info.profile_img });
  } catch (err) {
    console.error("Error updating profile image:", err);
    return res
      .status(500)
      .json({ error: "Failed to update profile image", details: err.message });
  }
});
//update profile route
// remeber you made a mistaje in twitter
server.post("/update-profile", verifyJwt, (req, res) => {
  let { username, bio, social_links } = req.body;
  let bioLimit = 150;

  if (username.length < 3) {
    return res
      .status(403)
      .json({ error: "username should be at leat 3 letters long" });
  }
  if (bio.length > bioLimit) {
    return res
      .status(403)
      .json({ error: `Bio should not be more than ${bioLimit}  characters` });
  }
  let socialLinksArr = Object.keys(social_links);

  try {
    for (let i = 0; i < socialLinksArr.length; i++) {
      if (social_links[socialLinksArr[i]].length) {
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

        if (
          !hostname.includes(`${socialLinksArr[i]}.com`) &&
          socialLinksArr[i] != "website" &&
          socialLinksArr[i] != "twitter"
        ) {
          //return an error
          return res.status(403).json({
            error: `${socialLinksArr[i]} link is invalid . You must enter a full link`,
          });
        }
      }
    }
  } catch (error) {
    return res.status(500).json({
      error: "You must provide full social links with http(S) included",
    });
  }
  let UpdateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links,
  };
  User.findOneAndUpdate({ _id: req.user }, UpdateObj, {
    runValidators: true,
  })
    .then(() => {
      return res.status(200).json({ username });
    })
    .catch((err) => {
      if (err.code == 1100) {
        return res.status(403).json({ error: "username is already taken" });
      } else {
        return res.status(500).json({ error: "username is already taken" });
      }
    });
});

//to create the blog
server.post("/create-blog", verifyJwt, (req, res) => {
  let authorId = req.user;

  if (!req.body) {
    return res.status(400).json({ error: "Request body is missing" });
  }

  let { title, des, banner, tags, content, draft, id } = req.body;
  let isDraft = Boolean(draft);

  if (!title || !title.length) {
    return res.status(403).json({ error: "You must provide a title" });
  }

  if (!Array.isArray(tags)) {
    return res.status(403).json({ error: "Tags must be an array" });
  }
  if (!isDraft && (!tags.length || tags.length > 10)) {
    return res.status(403).json({
      error: "Provide 1-10 tags to publish the blog",
    });
  }

  if (!isDraft) {
    if (!des || !des.length || des.length > 200) {
      return res.status(403).json({
        error: "You must provide a blog description under 200 characters",
      });
    }
    if (!banner || !banner.length) {
      return res.status(403).json({
        error: "You must provide a blog banner to publish",
      });
    }
    if (!content || !content.blocks || !content.blocks.length) {
      return res.status(403).json({
        error: "You must provide blog content to publish",
      });
    }
  }

  const today = new Date().toISOString().split("T")[0];

  User.findById(authorId)
    .then((user) => {
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      let updatedStreak = user.streak || { count: 1, lastPostDate: today };

      if (!isDraft) {
        const lastDate = user.streak?.lastPostDate;
        const streakCount = user.streak?.count || 0;

        if (lastDate == null) {
          // First post ever
          updatedStreak = {
            count: 1,
            lastPostDate: today,
          };
        } else {
          const diffInDays = Math.floor(
            (new Date(today) - new Date(lastDate)) / (1000 * 60 * 60 * 24)
          );

          if (diffInDays === 1) {
            updatedStreak = {
              count: streakCount + 1,
              lastPostDate: today,
            };
          } else if (diffInDays === 0) {
            updatedStreak = {
              count: streakCount,
              lastPostDate: today,
            };
          } else {
            updatedStreak = {
              count: 1,
              lastPostDate: today,
            };
            console.log("Streak reset");
          }
        }
      }
      console.log(updatedStreak, "hit");

      const processedTags = Array.isArray(tags)
        ? tags.map((tag) => tag.toLowerCase())
        : [];

      let blog_id =
        id ||
        title
          .replace(/[^a-zA-Z0-9]/g, " ")
          .replace(/\s+/g, "-")
          .trim() + nanoid().substring(0, 7);

      if (id) {
        // Update existing blog
        Blog.findOneAndUpdate(
          { blog_id },
          {
            title,
            des,
            banner,
            content,
            tags: processedTags,
            draft: isDraft,
          }
        )
          .then(() => {
            return res.status(200).json({ id: blog_id });
          })
          .catch((err) => {
            console.error("Update Blog Error:", err);
            return res.status(500).json({ error: err.message });
          });
      } else {
        // Create new blog
        let blog = new Blog({
          title,
          des,
          banner,
          content,
          tags: processedTags,
          author: authorId,
          blog_id,
          draft: isDraft,
        });

        blog
          .save()
          .then(() => {
            let incremental = isDraft ? 0 : 1;

            User.findOneAndUpdate(
              { _id: authorId },
              {
                $inc: { "account_info.total_posts": incremental },
                $push: { blogs: blog._id },
                streak: updatedStreak,
              }
            )
              .then(() => {
                return res.status(200).json({ id: blog.blog_id });
              })
              .catch((err) => {
                console.error("Update User Error:", err);
                return res
                  .status(500)
                  .json({ error: "Failed to update user data" });
              });
          })
          .catch((err) => {
            console.error("Save Blog Error:", err);
            return res.status(500).json({ error: err.message });
          });
      }
    })
    .catch((err) => {
      console.error("Find User Error:", err);
      return res.status(500).json({ error: "Failed to find user" });
    });
});

//get streaks
server.get("/streaks", verifyJwt, async (req, res) => {
  try {
    const userId = req.user;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    let streak = user.streak || { count: 0, lastPostDate: null };
    const today = new Date().toISOString().split("T")[0];

    // If streak has expired, reset it
    if (streak.lastPostDate) {
      const diffInDays = Math.floor(
        (new Date(today) - new Date(streak.lastPostDate)) /
          (1000 * 60 * 60 * 24)
      );

      if (diffInDays > 1) {
        streak = { count: 0, lastPostDate: streak.lastPostDate };

        // Update user in DB
        await User.findByIdAndUpdate(userId, { streak });
      }
    }

    // Message pools
    const newUserMessages = [
      "Let's light that streak 🔥 Start writing today!",
      "You haven’t posted yet — your journey begins now! 🚀",
      "No streak yet. One post is all it takes to start 💪",
      "You’re one blog away from starting a streak 🌱",
      "New here? Make your mark with your first post! ✨",
    ];

    const dayOneMessages = [
      "Day 1! A solid beginning 💥 Keep going!",
      "You've started your writing streak — awesome! ✍️",
      "The first post is done. Momentum is everything 💡",
      "You’re on the board — let’s keep that streak alive 🔄",
      "Just the beginning. Tomorrow is Day 2 🔥",
    ];

    const ongoingMessages = [
      "🔥 You're on a roll — {{count}} days straight!",
      "Amazing! {{count}} days of consistent writing 💪",
      "Keep the streak alive — Day {{count}} and counting 🚀",
      "💯 You're crushing it with {{count}} consecutive days!",
      "{{count}} days in. Your keyboard must be smoking! 🧠🔥",
      "Consistency looks good on you! Day {{count}} 🧱",
    ];

    const brokenStreakMessages = [
      "Oops, streak was broken. But today’s a fresh start 💡",
      "Streak reset — no worries, you’re back on track! 🚴‍♂️",
      "You missed a day, but your comeback starts now 💥",
      "Every legend slips — the streak is yours to rebuild 🔁",
      "Let’s get that streak going again. You’ve got this! 🛠️",
    ];

    const getRandom = (arr) => arr[Math.floor(Math.random() * arr.length)];

    let message;
    if (!streak.count || streak.count === 0) {
      message = getRandom(newUserMessages);
    } else if (streak.count === 1) {
      message = getRandom(dayOneMessages);
    } else if (streak.count > 1) {
      message = getRandom(ongoingMessages).replace("{{count}}", streak.count);
    } else {
      message = getRandom(brokenStreakMessages);
    }

    return res.status(200).json({ streak, message });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ err: error.message });
  }
});

//lederboard route
server.get("/leaderboard", async (req, res) => {
  try {
    const type = req.query.type || "streak"; // Default to 'streak'
    if (!["streak", "followers"].includes(type)) {
      return res
        .status(400)
        .json({ error: "Invalid type. Use 'streak' or 'followers'." });
    }

    let users;

    if (type === "streak") {
      const rawUsers = await User.find(
        {},
        "personal_info.fullname personal_info.username personal_info.profile_img  personal_info.isVerified streak"
      ).sort({ "streak.count": -1, "account_info.total_posts": -1 });

      const today = new Date().toISOString().split("T")[0];

      users = rawUsers
        .map((user) => {
          const lastDate = user.streak?.lastPostDate;
          const count = user.streak?.count || 0;

          const diffInDays = lastDate
            ? Math.floor(
                (new Date(today) - new Date(lastDate)) / (1000 * 60 * 60 * 24)
              )
            : Infinity;

          // Only return streak if it's within 1 day
          const validStreak =
            diffInDays <= 1
              ? { count, lastPostDate: lastDate }
              : { count: 0, lastPostDate: lastDate };

          return {
            _id: user._id,
            fullname: user.personal_info.fullname,
            username: user.personal_info.username,
            isVerified: user.personal_info.isVerified,
            profile_img: user.personal_info.profile_img,
            streak: validStreak,
          };
        })
        .filter((user) => user.streak.count > 0)
        .slice(0, 20);
    } else if (type === "followers") {
      users = await User.aggregate([
        {
          $project: {
            fullname: "$personal_info.fullname",
            username: "$personal_info.username",
            profile_img: "$personal_info.profile_img",
            isVerified: "$personal_info.isVerified",
            followersCount: { $size: { $ifNull: ["$followers", []] } },
          },
        },
        { $sort: { followersCount: -1, username: 1 } },
        { $limit: 20 },
      ]);
    }

    return res.status(200).json(users);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }
});

//get the blogs to display
server.post("/get-blog", (req, res) => {
  let { blog_id, draft, mode } = req.body;

  let incremental = mode != "edit" ? 1 : 0;

  Blog.findOneAndUpdate(
    { blog_id },
    { $inc: { "activity.total_reads": incremental } }
  )
    .populate(
      "author",
      "personal_info.fullname personal_info.username personal_info.profile_img "
    )
    .select("title des content banner activity publishedAt blog_id tags")
    .then((blog) => {
      User.findOneAndUpdate(
        { "personal_info.username": blog.author.personal_info.username },
        {
          $inc: { "account_info.total_reads": incremental },
        }
      ).catch((err) => {
        return res.status(500).json({ error: err.message });
      });

      if (blog.draft && !draft) {
        return res.status(500).json({ error: "you can not access draft blog" });
      }

      return res.status(200).json({ blog });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//like route
server.post("/like-blog", verifyJwt, async (req, res) => {
  try {
    const user_id = req.user; // ID of the user who liked the blog
    const { _id, islikedByUser } = req.body;
    const incremental = !islikedByUser ? 1 : -1;

    // Update blog like count
    const blog = await Blog.findOneAndUpdate(
      { _id },
      { $inc: { "activity.total_likes": incremental } },
      { new: true }
    );

    if (!blog) return res.status(404).json({ error: "Blog not found" });

    // When the user LIKES a blog
    if (!islikedByUser) {
      // 1️⃣ Save the like notification in DB
      const like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id,
      });
      await like.save();

      // 2️⃣ Fetch the user info (who liked the blog)
      const user = await User.findById(user_id).select(
        "personal_info.fullname personal_info.username"
      );

      // 3️⃣ Get tokens of the blog author
      const tokens = await Token.find({ user: blog.author }).select(
        "token -_id"
      );
      const tokenList = tokens.map((t) => t.token);

      if (tokenList.length > 0) {
        // 4️⃣ Build the notification message
        const message = {
          notification: {
            title: `${user.personal_info.fullname || user.personal_info.username} liked your blog ❤️`,
            body: "Your blog just received a new like!",
          },
          data: {
            url: process.env.VITE_CLIENT_DOMAIN + "/dashboard/notifications", // ✅ accessible on client as payload.data.link
          },
          tokens: tokenList,
        };

        // 5️⃣ Send push notification
        const response = await admin.messaging().sendEachForMulticast(message);

        console.log(
          "Push notification detailed response:",
          JSON.stringify(response, null, 2)
        );

        // 🔄 Cleanup invalid tokens
        response.responses.forEach(async (r, i) => {
          if (
            !r.success &&
            ["InvalidRegistration", "NotRegistered"].includes(r.error.code)
          ) {
            await Token.deleteOne({ token: tokenList[i] });
            console.log("Deleted invalid token:", tokenList[i]);
          }
        });
      }

      return res.status(200).json({ liked_by_user: true });
    } else {
      // When the user UNLIKES
      await Notification.findOneAndDelete({
        user: user_id,
        type: "like",
        blog: _id,
      });

      return res.status(200).json({ liked_by_user: false });
    }
  } catch (err) {
    console.error("Error in like-blog:", err);
    return res.status(500).json({ error: err.message });
  }
});

server.post("/isliked-by-user", verifyJwt, (req, res) => {
  let user_id = req.user;

  let { _id } = req.body;
  Notification.exists({ user: user_id, type: "like", blog: _id })
    .then((result) => {
      return res.status(200).json({ result });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//comments route
server.post("/add-comment", verifyJwt, async (req, res) => {
  try {
    const user_id = req.user;
    const { _id, comment, blog_author, replying_to, notification_id } = req.body;

    if (!comment?.length) {
      return res.status(403).json({ error: "Write something to leave a comment" });
    }

    // 🧩 If replying, ensure parent exists
    let replyingToCommentDoc = null;
    if (replying_to) {
      replyingToCommentDoc = await Comment.findById(replying_to);
      if (!replyingToCommentDoc) {
        return res.status(404).json({ error: "Parent comment not found" });
      }
    }

    // ✅ Create new comment
    const commentObj = new Comment({
      blog_id: _id,
      blog_author,
      comment,
      commented_by: user_id,
      ...(replying_to && { parent: replying_to, isReply: true }),
    });

    const commentFile = await commentObj.save();
    const { comment: commentText, commentedAt, children } = commentFile;

    // 🔢 Update blog stats
    await Blog.findByIdAndUpdate(_id, {
      $push: { comments: commentFile._id },
      $inc: {
        "activity.total_comments": 1,
        "activity.total_parent_comments": replying_to ? 0 : 1,
      },
    });

    // 🔔 Create in-app notification
    const notificationObj = {
      type: replying_to ? "reply" : "comment",
      blog: _id,
      notification_for: replying_to
        ? replyingToCommentDoc.commented_by
        : blog_author,
      user: user_id,
      comment: commentFile._id,
      ...(replying_to && { replied_on_comment: replying_to }),
    };

    // 🧩 Update parent comment’s children if reply
    if (replying_to) {
      await Comment.findByIdAndUpdate(replying_to, {
        $push: { children: commentFile._id },
      });

      if (notification_id) {
        await Notification.findByIdAndUpdate(notification_id, {
          reply: commentFile._id,
        });
        console.log("notification updated");
      }
    }

    await new Notification(notificationObj).save();
    console.log("new notification created");

    // 🔍 Get commenter info for notification title
    const commenter = await User.findById(user_id).select(
      "personal_info.fullname personal_info.username"
    );

    // 🧠 Determine who should receive this notification
    const recipientId = replying_to
      ? replyingToCommentDoc.commented_by
      : blog_author;

    // 🎯 Get recipient tokens
    const tokens = await Token.find({ user: recipientId }).select("token -_id");
    const tokenList = tokens.map((t) => t.token);

    if (tokenList.length > 0) {
      // 📲 Build push notification
      const message = {
        notification: {
          title: `${commenter.personal_info.fullname || commenter.personal_info.username} commented on your blog 💬`,
          body: replying_to
            ? "They replied to your comment!"
            : "You have a new comment on your blog.",
        },
        data: {
          url: process.env.VITE_CLIENT_DOMAIN + "/dashboard/notifications",
        },
        webpush: {
          fcmOptions: {
            link: process.env.VITE_CLIENT_DOMAIN + "/dashboard/notifications",
          },
        },
        tokens: tokenList,
      };

      // 🚀 Send via Firebase
      const response = await admin.messaging().sendEachForMulticast(message);
      console.log("Push notification detailed response:", JSON.stringify(response, null, 2));

      // 🧹 Remove invalid tokens
      for (let i = 0; i < response.responses.length; i++) {
        const r = response.responses[i];
        if (!r.success && ["messaging/registration-token-not-registered", "messaging/invalid-registration-token"].includes(r.error?.code)) {
          await Token.deleteOne({ token: tokenList[i] });
          console.log("Deleted invalid token:", tokenList[i]);
        }
      }
    }

    // ✅ Return comment info
    return res.status(200).json({
      comment: commentText,
      commentedAt,
      _id: commentFile._id,
      user_id,
      children,
    });
  } catch (error) {
    console.error("Error in add-comment:", error.message);
    return res.status(500).json({ error: error.message });
  }
});


server.post("/get-blog-comments", (req, res) => {
  let { blog_id, skip } = req.body;
  let maxLimit = 10;

  Comment.find({ blog_id, isReply: false })
    .populate(
      "commented_by",
      "personal_info.username personal_info.fullname personal_info.profile_img"
    )
    .skip(skip)
    .limit(maxLimit)
    .sort({
      commentedAt: -1,
    })
    .then((comment) => {
      return res.status(200).json(comment);
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

//get replies
server.post("/get-replies", (req, res) => {
  let { _id, skip } = req.body;
  let maxLimit = 5;

  Comment.findOne({ _id })
    .populate({
      path: "children",
      options: {
        limit: maxLimit,
        skip: skip,
        sort: { commentedAt: -1 },
      },
      populate: {
        path: "commented_by",
        select:
          "personal_info.profile_img personal_info.fullname personal_info.username",
      },
      select: "-blog_id -updatedAt",
    })
    .select("children")

    .then((doc) => {
      console.log(doc);

      return res.status(200).json({ replies: doc.children });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

//delete comments
const deleteComments = (_id) => {
  Comment.findOneAndDelete({ _id })
    .then((comment) => {
      if (comment.parent) {
        Comment.findOneAndUpdate(
          { _id: comment.parent },
          { $pull: { children: _id } }
        )
          .then((data) => console.log("comment delete from parent "))
          .catch((err) => console.log(err));
      }
      Notification.findOneAndDelete({ comment: _id }).then((notification) =>
        console.log("comment notification deleted ")
      );
      Notification.findOneAndUpdate(
        { reply: _id },
        { $unset: { reply: 1 } }
      ).then((notification) => console.log("reply notification deleted "));

      Blog.findOneAndUpdate(
        { _id: comment.blog_id },
        {
          $pull: { comments: _id },
          $inc: { "activity.total_comments": -1 },
          "activity.total_parent_comments": comment.parent ? 0 : -1,
        }
      ).then((blog) => {
        if (comment.children.length) {
          comment.children.map((replies) => {
            deleteComments(replies);
          });
        }
      });
    })
    .catch((err) => {
      console.log(err.message);
    });
};
server.post("/delete-comment", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { _id } = req.body;

  Comment.findOne({ _id }).then((comment) => {
    if (!comment) {
      return res.status(404).json({ error: "Comment not found" });
    }
    if (user_id == comment.commented_by || user_id == comment.blog_author) {
      deleteComments(_id);
      return res.status(200).json({ status: "done" });
    } else {
      return res.status(403).json({ error: "You can  not delete comment" });
    }
  });
});

//for notifications
server.get("/new-notification", verifyJwt, (req, res) => {
  let user_id = req.user;
  Notification.exists({
    $or: [
      {
        notification_for: user_id,
        seen: false,
        user: { $ne: user_id },
      },
      { isGlobal: true, seen: false },
    ],
  })
    .then((result) => {
      if (result) {
        return res.status(200).json({ new_notification_available: true });
      } else {
        return res.status(200).json({ new_notification_available: false });
      }
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

//get notifications
server.post("/notifications", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { page, filter, deletedDocCount } = req.body;
  let maxLimit = 20;

  // let findQuery = { notification_for: user_id, user: { $ne: user_id } };
  const findQuery = {
    $or: [
      {
        notification_for: user_id,
        user: {
          $ne: user_id,
        },
      },
      { isGlobal: true },
    ],
  };
  let skipDocs = (page - 1) * maxLimit;
  if (filter != "all") {
    findQuery.type = filter;
  }
  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }
  Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .populate(
      "user",
      "personal_info.fullname personal_info.username personal_info.profile_img "
    )
    .populate("comment", "comment")
    .populate("replied_on_comment", "comment")
    .populate("reply", "comment")
    .populate({
      path: "reply",
      populate: {
        path: "commented_by",
        select:
          "personal_info.fullname personal_info.username personal_info.profile_img",
      },
    })
    .sort({ createdAt: -1 })
    .select("createdAt type seen reply title message isGlobal")
    .then((notifications) => {
      Notification.updateMany(findQuery, { seen: true })
        .skip(skipDocs)
        .limit(maxLimit)
        .then(() => console.log("notifications seen"));
      return res.status(200).json({ notifications });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//make an annoucement
server.post("/make-annoucement", verifyJwt, async (req, res) => {
  try {
    let { title, message } = req.body;

    let notification = new Notification({
      type: "info",
      title,
      message,
      isGlobal: true,
      user: req.user,
    });
    await notification.save();
    return res.status(200).json("notification saved successfully");
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
//count notifications
server.post("/all-notifications-count", verifyJwt, (req, res) => {
  let user_id = req.user;

  let { filter } = req.body;
  let findQuery = { notification_for: user_id, user: { $ne: user_id } };
  if (filter != "all") {
    findQuery.type = filter;
  }
  Notification.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//to manage blogs
server.post("/user-written-blogs", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { page, draft, query, deletedDocCount } = req.body;

  let maxLimit = 10;
  let skipDocs = (page - 1) * maxLimit;

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }
  Blog.find({ author: user_id, draft, title: new RegExp(query, "i") })
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select("title banner publishedAt blog_id activity des draft -_id")
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});
server.post("/user-written-blogs-count", verifyJwt, (req, res) => {
  let user_id = req.user;

  let { draft, query } = req.body;

  Blog.countDocuments({
    author: user_id,
    draft,
    title: new RegExp(query, "i"),
  })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

//delete blogs
server.post("/delete-blog", verifyJwt, (req, res) => {
  let user_id = req.user;
  let { blog_id } = req.body;

  Blog.findOneAndDelete({ blog_id })
    .then((blog) => {
      Notification.deleteMany({ blog: blog._id }).then((data) =>
        console.log("notifications deleted")
      );
      Comment.deleteMany({ blog_id: blog._id }).then((data) =>
        console.log("comments deleted")
      );
      User.findOneAndUpdate(
        { _id: user_id },
        { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } }
      ).then((user) => console.log("Blog Deleted"));
      return res.status(202).json({ status: "done" });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

//upload image competion
server.post(
  "/upload-image-competition",
  verifyJwt,
  upload.single("image"),
  async (req, res) => {
    try {
      const user_id = req.user; // assuming `verifyJwt` sets `req.user`

      // Check if user already submitted this week
      const start = startOfWeek(new Date(), { weekStartsOn: 1 }); // Monday
      const end = endOfWeek(new Date(), { weekStartsOn: 1 });

      const existing = await Challenge.findOne({
        posted_by: user_id,
        createdAt: { $gte: start, $lte: end },
      });

      if (existing) {
        return res.status(400).json({
          error: "You can only submit one photo per week.",
        });
      }
      const image = req.file;
      if (!image) {
        return res.status(400).json({ error: "Image is required" });
      }

      const bufferStream = new Readable();
      bufferStream.push(image.buffer);
      bufferStream.push(null);

      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: "user_images",
          public_id: `user_${nanoid()}`,
          transformation: [{ width: 500, height: 500, crop: "limit" }],
        },
        async (error, result) => {
          if (error) {
            console.error("Cloudinary Upload Error:", error);
            return res.status(500).json({ error: "Upload failed" });
          }

          // Save to MongoDB
          const newChallenge = new Challenge({
            imageurl: result.secure_url,
            posted_by: user_id,
          });

          await newChallenge.save();

          return res.status(200).json({
            message: "Image uploaded and saved successfully",
            imageUrl: result.secure_url,
          });
        }
      );

      bufferStream.pipe(uploadStream);
    } catch (error) {
      console.error("Server Error:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

server.get("/get-competition-images", async (req, res) => {
  try {
    const start = startOfWeek(new Date(), { weekStartsOn: 1 }); // Monday
    const end = endOfWeek(new Date(), { weekStartsOn: 1 });
    const challenges = await Challenge.find({
      createdAt: { $gte: start, $lte: end },
    })
      .populate("posted_by", "personal_info.username personal_info.profile_img")
      .sort({ createdAt: -1 });

    return res.status(200).json({ challenges });
  } catch (error) {
    console.error("Error fetching competition images:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});
//assign ranks
server.post("/assign-ranks", async (req, res) => {
  try {
    const { ranks } = req.body; // { challengeId: rank }

    if (!ranks || Object.keys(ranks).length === 0) {
      return res.status(400).json({ error: "No ranks provided" });
    }

    // Prevent duplicate ranks
    const uniqueRanks = new Set(Object.values(ranks));
    if (uniqueRanks.size !== Object.keys(ranks).length) {
      return res.status(400).json({ error: "Duplicate ranks not allowed" });
    }

    // Update each challenge with its rank
    const updates = Object.entries(ranks).map(([id, rank]) =>
      Challenge.findByIdAndUpdate(id, { $set: { rank } })
    );

    await Promise.all(updates);
    const start = startOfWeek(new Date(), { weekStartsOn: 1 }); // Monday
    const end = endOfWeek(new Date(), { weekStartsOn: 1 });
    // 🔹 Find all winners (1st, 2nd, 3rd)
    const winners = await Challenge.find({
      createdAt: { $gte: start, $lte: end },
      rank: { $gt: 0, $lte: 3 },
    })
      .sort({ rank: 1 })
      .populate(
        "posted_by",
        "personal_info.username personal_info.fullname personal_info.profile_img"
      );

    // Build the message for the global notification
    let message = "";
    winners.forEach((winner) => {
      if (winner.rank === 1)
        message += `🏆 1st Place: ${winner.posted_by.personal_info.fullname} (@${winner.posted_by.personal_info.username})\n`;
      else if (winner.rank === 2)
        message += `🥈 2nd Place: ${winner.posted_by.personal_info.fullname} (@${winner.posted_by.personal_info.username})\n`;
      else if (winner.rank === 3)
        message += `🥉 3rd Place: ${winner.posted_by.personal_info.fullname} (@${winner.posted_by.personal_info.username})\n`;
    });

    if (!message) message = "No winners found.";

    // 🔹 Create a global notification
    const notification = new Notification({
      type: "info",
      title: "🎉 Winners of the Face of The Week Challenge!",
      message,
      isGlobal: true,
      user: req.user, // Admin who created it
    });

    await notification.save();

    return res.status(200).json({
      message: "Ranks assigned and winners announced successfully 🎉",
      winners,
    });
  } catch (error) {
    console.error("Error assigning ranks:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

//get the winners
server.get("/get-winners", async (req, res) => {
  try {
    const start = startOfWeek(new Date(), { weekStartsOn: 1 }); // Monday
    const end = endOfWeek(new Date(), { weekStartsOn: 1 });

    const winners = await Challenge.find({
      createdAt: { $gte: start, $lte: end },
      rank: { $gt: 0 },
    })
      .sort({ rank: 1 })
      .populate(
        "posted_by",
        "personal_info.username personal_info.profile_img personal_info.fullname"
      )
      .limit(4); // Get top 4 winners

    return res.status(200).json({ winners });
  } catch (error) {
    console.error("Error fetching winners:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

//get all time winners
server.get("/all-time-winners", async (req, res) => {
  try {
    const winners = await Challenge.find({ rank: { $gt: 0, $lt: 2 } })
      .sort({ rank: 1 })
      .populate(
        "posted_by",
        "personal_info.username personal_info.profile_img personal_info.fullname"
      )
      .limit(4); // Get top 3 winners

    return res.status(200).json({ winners });
  } catch (error) {
    console.error("Error fetching all-time winners:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

//get messages dm
server.post("/get-messages", verifyJwt, async (req, res) => {
  try {
    const { id, isGroup = false } = req.body; // Add isGroup flag to differentiate
    const user1 = new mongoose.Types.ObjectId(req.user); // Convert to ObjectId

    // Validate inputs
    if (!id) {
      return res.status(400).json({ error: "Chat ID is required" });
    }

    let query;
    if (isGroup) {
      // Group chat: use room field
      query = { room: id };
    } else {
      // Direct chat: use sender/recipient
      const user2 = mongoose.isValidObjectId(id)
        ? new mongoose.Types.ObjectId(id)
        : null;
      if (!user2) {
        return res.status(400).json({ error: "Invalid user ID" });
      }

      // Mark direct messages as read
      await Messages.updateMany(
        { recipient: user1, sender: user2, isRead: false },
        { isRead: true }
      );

      query = {
        $or: [
          { sender: user1, recipient: user2 },
          { sender: user2, recipient: user1 },
        ],
      };
    }

    // Fetch messages
    const messages = await Messages.find(query)
      .populate(
        "sender",
        "personal_info.username personal_info.profile_img personal_info.fullname"
      )
      .sort({ createdAt: 1 })
      .limit(req.body.limit || 50) // Default limit of 50 messages
      .skip(req.body.skip || 0); // Support pagination

    return res.status(200).json({ messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});
//get message notification
server.get("/has-unread", verifyJwt, async (req, res) => {
  try {
    // Convert req.user to ObjectId
    const userId = mongoose.isValidObjectId(req.user)
      ? new mongoose.Types.ObjectId(req.user)
      : null;
    if (!userId) {
      return res
        .status(401)
        .json({ status: "error", error: "Invalid user authentication" });
    }

    // Query for any unread messages where the user is the recipient
    const query = {
      recipient: userId,
      isRead: false,
    };

    const hasUnread = await Messages.exists(query);

    return res.status(200).json({ hasUnread: !!hasUnread });
  } catch (error) {
    console.error("Error checking unread messages:", error.message);
    return res
      .status(500)
      .json({ status: "error", error: "Internal server error" });
  }
});

//get the contacts
server.post("/get-contacts", verifyJwt, async (req, res) => {
  try {
    let user1 = req.user;
    user1 = new mongoose.Types.ObjectId(user1);

    const contacts = await Messages.aggregate([
      {
        $match: {
          $or: [{ sender: user1 }, { recipient: user1 }],
        },
      },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: {
            $cond: [{ $eq: ["$sender", user1] }, "$recipient", "$sender"],
          },
          lastMessageTime: { $first: "$createdAt" },
          lastMessage: { $first: "$content" },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "contactInfo",
        },
      },
      { $unwind: "$contactInfo" },
      {
        $lookup: {
          from: "messages",
          let: { contactId: "$_id" },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ["$sender", "$$contactId"] },
                    { $eq: ["$recipient", user1] },
                    { $eq: ["$isRead", false] },
                  ],
                },
              },
            },
            { $count: "unreadCount" },
          ],
          as: "unreadData",
        },
      },
      {
        $addFields: {
          unreadCount: {
            $ifNull: [{ $arrayElemAt: ["$unreadData.unreadCount", 0] }, 0],
          },
        },
      },
      {
        $project: {
          _id: 1,
          lastMessageTime: 1,
          lastMessage: 1,
          unreadCount: 1,
          email: "$contactInfo.personal_info.email",
          firstName: "$contactInfo.personal_info.fullname",
          profileImage: "$contactInfo.personal_info.profile_img",
          isVerified: "$contactInfo.personal_info.isVerified",
          username: "$contactInfo.personal_info.username",
          lastSeen: "$contactInfo.lastSeen",
        },
      },
      { $sort: { lastMessageTime: -1 } },
    ]);

    // ✅ Append online status from socket map
    contacts.forEach((contact) => {
      contact.online = userSocketMap.has(contact._id.toString());
    });

    return res.status(200).json({ contacts });
  } catch (error) {
    console.error("get-contacts error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.post("/get-anonymous", async (req, res) => {
  let { page = 1 } = req.body;
  let maxLimit = 20;
  let skipDocs = (page - 1) * maxLimit;

  try {
    const messages = await Anonymous.find()
      .skip(skipDocs)
      .limit(maxLimit)
      .sort({ createdAt: -1 });

    const onlineCount = userSocketMap.size;
    const totalMessages = await Anonymous.countDocuments();

    // Use date-fns to get this week's Monday (start) and Sunday (end)
    const now = new Date();
    const weekStart = startOfWeek(now, { weekStartsOn: 1 }); // Monday
    const weekEnd = endOfWeek(now, { weekStartsOn: 1 }); // Sunday

    const weeklyMessages = await Anonymous.countDocuments({
      createdAt: { $gte: weekStart, $lte: weekEnd },
    });

    return res.status(200).json({
      messages,
      totalMessages,
      weeklyMessages,
      onlineCount,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

//get shared message
server.post("/anonymous/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const message = await Anonymous.findById(id);
    if (!message) {
      return res.status(404).json({ error: "Message not found" });
    }
    res.json({ text: message });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

//like the anonymous messages
server.post("/like-anonymous", verifyJwt, async (req, res) => {
  try {
    const userId = req.user;
    const { messageId } = req.body;
    console.log(messageId);

    if (!messageId) {
      return res.status(400).json({ error: "Message ID is required" });
    }

    const message = await Anonymous.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: "Message not found" });
    }

    // Optional: Check if user already liked it (if you store likedBy array)
    if (message.likedBy.includes(userId)) {
      return res.status(400).json({ error: "Already liked" });
    }

    // Increment likes
    message.likes = (message.likes || 0) + 1;
    // Optionally add user to likedBy
    message.likedBy.push(userId);

    await message.save();

    return res.status(200).json({ message: "Liked successfully" });
  } catch (error) {
    console.error("Like error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

//forgot-password
server.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ "personal_info.email": email });
    if (!user) {
      return res.status(404).json({ error: "user not found" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiresAt = Date.now() + 24 * 60 * 60 * 1000; //i hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = resetTokenExpiresAt;

    await user.save();

    const resetLink = `${process.env.VITE_CLIENT_DOMAIN}/reset-password/${resetToken}`;
    const resend = new Resend(process.env.RESEND_API_KEY);

    await resend.emails.send({
      from: "support@campus-connect.xyz",
      to: email,
      subject: "Reset your password",
      html: `
        <p>Hello,</p>
        <p>Click the link below to reset your password:</p>
        <a href="${resetLink}">Reset Password</a>
        <p>If you didn’t request this, you can ignore this email.</p>
      `,
    });

    res.status(200).json({
      success: true,
      message: "password reset link sent to your email",
    });
  } catch (error) {
    console.log(`Error in sending email,${error}`);

    res.status(500).json({
      success: false,
      message: "server error",
    });
  }
});

//reset-password
server.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params; // called it token because we put /:token in the post request
    const { password } = req.body;

    if (!passwordRegex.test(password)) {
      return res.status(403).json({
        error:
          "Password should be 6 to 20 letters long with a numeric,1 lowercase and 1 uppercase letters ",
      });
    }
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiresAt: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    user.personal_info.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpiresAt = undefined;
    await user.save();
    res
      .status(200)
      .json({ success: true, message: "password reset successsful" });
  } catch (error) {
    console.log("error in resetPassword", error);
    res.status(400).json({ success: false, message: error.message });
  }
});

server.post("/save-token", verifyJwt, async (req, res) => {
  try {
    const user_id = req.user; // from verifyJwt
    const { token } = req.body;

    if (!token) return res.status(400).json({ error: "Token required" });

    const exists = await Token.findOne({ token, user: user_id });
    if (!exists) {
      await Token.create({ user: user_id, token });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to save token" });
  }
});
server.post("/send-notification", async (req, res) => {
  const { title, body } = req.body;
  const tokens = await Token.find().select("token -_id");
  const tokenList = tokens.map((t) => t.token);

  if (tokenList.length === 0)
    return res.status(400).json({ error: "No tokens" });

  const message = {
    notification: { title, body },
    tokens: tokenList,
  };

  try {
    const response = await admin.messaging().sendEachForMulticast(message);
    res.json({ success: true, response });
  } catch (err) {
    console.error("Error sending message:", err);
    res.status(500).json({ error: "Failed to send notification" });
  }
});

// server.post("/broadcast-message", verifyJwt, async (req, res) => {
//   try {
//     const adminId = req.user; // must be an admin
//     const { message } = req.body;

//     if (!message || message.trim() === "") {
//       return res.status(400).json({ error: "Message content is required" });
//     }

//     const users = await User.find({ _id: { $ne: adminId } }).select("_id");

//     const batchSize = 500;
//     for (let i = 0; i < users.length; i += batchSize) {
//       const batch = users.slice(i, i + batchSize);

//       const messagesToInsert = batch.map((user) => ({
//         sender: adminId,
//         recipient: user._id,
//         content: message,
//         messageType: "text",
//         isRead: false,
//         createdAt: new Date(),
//       }));

//       await Messages.insertMany(messagesToInsert);
//     }

//     return res.status(200).json({ message: "Broadcast sent to all users." });
//   } catch (error) {
//     console.error("Broadcast error:", error);
//     return res.status(500).json({ error: "Internal server error" });
//   }
// });

// Connect to DB

//

mongoose
  .connect(process.env.DB_LOCATION, { autoIndex: true })
  .then(() => console.log("Database connected successfully"))
  .catch((err) => console.error("Database connection error:", err));

socketServer.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const io = new SocketIoServer(socketServer, {
  cors: {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("CORS not allowed"));
      }
    },
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const userSocketMap = new Map();

const disconnect = async (socket) => {
  console.log(`Client Disconnected: ${socket.id}`);
  for (const [userId, socketId] of userSocketMap.entries()) {
    if (socketId === socket.id) {
      userSocketMap.delete(userId);
      await User.findByIdAndUpdate(userId, { lastSeen: new Date() });
      break;
    }
  }
};
const sendMessage = async (message) => {
  const senderSocketId = userSocketMap.get(message.sender);
  const recipientSocketId = userSocketMap.get(message.recipient);

  // 1️⃣ Create and fetch the message with sender/recipient populated
  const createdMessage = await Messages.create(message);

  const messageData = await Messages.findById(createdMessage._id)
    .populate(
      "sender",
      "personal_info.username personal_info.profile_img personal_info.fullname"
    )
    .populate(
      "recipient",
      "personal_info.username personal_info.profile_img personal_info.fullname"
    );

  // 2️⃣ Emit the message via Socket.IO (real-time)
  if (recipientSocketId) io.to(recipientSocketId).emit("receivedMessage", messageData);
  if (senderSocketId) io.to(senderSocketId).emit("receivedMessage", messageData);

  // 3️⃣ Send Push Notification via Firebase Admin SDK
  try {
    const tokens = await Token.find({ user: message.recipient }).select("token -_id");
    const tokenList = tokens.map((t) => t.token);

    if (tokenList.length > 0) {
      const senderName =
        messageData.sender.personal_info.fullname ||
        messageData.sender.personal_info.username ||
        "Someone";

      const pushMessage = {
        notification: {
          title: `${senderName} sent you a message 💬`,
          body: messageData.content || "You have a new message!",
        },
        data: {
          url: process.env.VITE_CLIENT_DOMAIN + `/messages/${message.sender}`,
        },
        tokens: tokenList,
      };

      const response = await admin.messaging().sendEachForMulticast(pushMessage);

      console.log("Push notification sent:", JSON.stringify(response, null, 2));

      // 🔄 Clean up invalid tokens
      response.responses.forEach(async (r, i) => {
        if (
          !r.success &&
          ["InvalidRegistration", "NotRegistered"].includes(r.error.code)
        ) {
          await Token.deleteOne({ token: tokenList[i] });
          console.log("Deleted invalid token:", tokenList[i]);
        }
      });
    }
  } catch (err) {
    console.error("Error sending push notification:", err);
  }
};


const AnonymousMessage = async ({ content, date, sender, likes, colors }) => {
  try {
    if (!content) {
      return console.log("No content provided in anonymousMessage");
    }
    const messageData = await Anonymous.create({
      content,
      date,
      sender,
      likes,
      colors,
    });
    io.emit("anonymousMessage", messageData);
    return;
  } catch (error) {
    console.log(error);
    return;
  }
};

io.on("connection", (socket) => {
  const userId = socket.handshake.query.userId;
  socket.join("global");

  if (userId) {
    userSocketMap.set(userId, socket.id);
    console.log(`User connected ${userId} with socketId: ${socket.id}`);
  } else {
    console.log("User ID not provided during connection");
  }

  socket.on(
    "sendGroupMessage",
    async ({ content, senderId, messageType, fileUrl, room }) => {
      const msg = await Messages.create({
        content,
        sender: senderId,
        recipient: null, // Group messages typically don’t have a single recipient
        room: room || "global", // Fallback to "global" if no room is specified
        messageType,
        fileUrl,
      });

      const populated = await msg.populate("sender", "personal_info.fullname");
      io.to(room || "global").emit("receiveGroupMessage", populated);
    }
  );
  socket.on("anonymousMessage", AnonymousMessage);
  socket.on("sendMessage", sendMessage);
  socket.on("disconnect", () => disconnect(socket));
});
