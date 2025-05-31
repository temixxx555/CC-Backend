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
import { error, log } from "console";
import { setServers } from "dns";

dotenv.config();

const server = express();
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
  "https://campusconnect1.vercel.app", // Production frontend
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
    console.log("Upload route hit");
    console.log("req.file:", req.file);

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
  let maxLimit = 5;
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      return res.status(500).json({ err: err.message });
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
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({
      "activity.total_read": -1,
      "activity.total_likes": -1,
      publishedAt: -1,
    })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .limit(5)
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
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
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

  // Check if req.body exists
  if (!req.body) {
    return res.status(400).json({ error: "Request body is missing" });
  }

  let { title, des, banner, tags, content, draft, id } = req.body;
  let isDraft = Boolean(draft);

  // Log request body for debugging
  console.log("Request body:", req.body);

  // Validate title
  if (!title || !title.length) {
    return res.status(403).json({ error: "You must provide a title" });
  }

  // Validate tags (apply to both draft and published blogs)
  if (!Array.isArray(tags)) {
    return res.status(403).json({ error: "Tags must be an array" });
  }
  if (!isDraft && (!tags.length || tags.length > 10)) {
    return res.status(403).json({
      error: "Provide 1-10 tags to publish the blog",
    });
  }

  // Validate other fields for non-draft blogs
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

  // Process tags (convert to lowercase, ensure it's an array)
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
      { title, des, banner, content, tags: processedTags, draft: isDraft }
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
          }
        )
          .then(() => {
            return res.status(200).json({ id: blog.blog_id });
          })
          .catch((err) => {
            console.error("Update User Error:", err);
            return res
              .status(500)
              .json({ error: "Failed to update total post number" });
          });
      })
      .catch((err) => {
        console.error("Save Blog Error:", err);
        return res.status(500).json({ error: err.message });
      });
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
server.post("/like-blog", verifyJwt, (req, res) => {
  let user_id = req.user;

  let { _id, islikedByUser } = req.body;
  let incremental = !islikedByUser ? 1 : -1;

  Blog.findOneAndUpdate(
    { _id },
    { $inc: { "activity.total_likes": incremental } }
  ).then((blog) => {
    if (!islikedByUser) {
      let like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id,
      });
      like.save().then((notification) => {
        return res.status(200).json({ liked_by_user: true });
      });
    } else {
      Notification.findOneAndDelete({ user: user_id, type: "like", blog: _id })
        .then((data) => {
          return res.status(200).json({ liked_by_user: false });
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });
    }
  });
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
  let user_id = req.user;
  let { _id, comment, blog_author, replying_to, notification_id } = req.body;

  if (!comment.length) {
    return res
      .status(403)
      .json({ error: "Write something to leave a comment" });
  }

  // 🧠 If replying, validate parent exists before continuing
  let replyingToCommentDoc = null;
  if (replying_to) {
    replyingToCommentDoc = await Comment.findById(replying_to);
    if (!replyingToCommentDoc) {
      return res.status(404).json({ error: "Parent comment not found" });
    }
  }

  // ✅ Create the comment
  const commentObj = new Comment({
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id,
    ...(replying_to && {
      parent: replying_to,
      isReply: true,
    }),
  });

  commentObj.save().then(async (commentFile) => {
    const { comment, commentedAt, children } = commentFile;

    await Blog.findByIdAndUpdate(_id, {
      $push: { comments: commentFile._id },
      $inc: {
        "activity.total_comments": 1,
        "activity.total_parent_comments": replying_to ? 0 : 1,
      },
    });

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

    // Push child to parent's children array if it's a reply
    if (replying_to) {
      await Comment.findByIdAndUpdate(replying_to, {
        $push: { children: commentFile._id },
      });
      if (notification_id) {
        Notification.findOneAndUpdate(
          { _id: notification_id },
          { reply: commentFile._id }
        ).then((notification) => {
          console.log("notification updated");
        });
      }
    }

    await new Notification(notificationObj).save();
    console.log("new notification created");

    return res.status(200).json({
      comment,
      commentedAt,
      _id: commentFile._id,
      user_id,
      children,
    });
  });
});

server.post("/get-blog-comments", (req, res) => {
  let { blog_id, skip } = req.body;
  let maxLimit = 5;

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
    notification_for: user_id,
    seen: false,
    user: { $ne: user_id },
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
  let maxLimit = 10;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };
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
    .select("createdAt type seen reply")
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

  let maxLimit = 5;
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

//delet blogs
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
// Connect to DB
mongoose
  .connect(process.env.DB_LOCATION, { autoIndex: true })
  .then(() => console.log("Database connected successfully"))
  .catch((err) => console.error("Database connection error:", err));

server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
