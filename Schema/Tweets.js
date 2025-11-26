import mongoose, { Schema } from "mongoose";

const tweetSchema = new Schema({
  tweet_id: {
    type: String,
    required: true,
    unique: true,
  },
  text: {
    type: String,
    required: true,
    maxlength: 300,
  },
  images: {
    type: [String], // array of strings
    validate: {
      validator: function(arr) {
        return arr.length <= 4; // max 4 images
      },
      message: 'Cannot upload more than 4 images'
    }
  },
  author: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: 'users',
    index: true
  },
  activity: {
    total_likes: { type: Number, default: 0 },
    total_comments: { type: Number, default: 0 },
    total_retweets: { type: Number, default: 0 },
    total_views: { type: Number, default: 0 },
    likedBy: [{ type: Schema.Types.ObjectId, ref: "users" }],
    retweetedBy: [{ type: Schema.Types.ObjectId, ref: "users" }],
  },
  
  // For threading/replies
  reply_to: {
    type: Schema.Types.ObjectId,
    ref: 'tweets',
    default: null
  },
  
  // Reuse your existing comments system
  comments: [{ type: Schema.Types.ObjectId, ref: 'comments' }],
  
  draft: { type: Boolean, default: false }
}, 
{ 
  timestamps: { createdAt: 'publishedAt' } 
});

// Indexes for performance
tweetSchema.index({ author: 1, publishedAt: -1 }); // user timeline
tweetSchema.index({ publishedAt: -1 }); // home feed
tweetSchema.index({ reply_to: 1 }); // thread queries

export default mongoose.model("tweets", tweetSchema);