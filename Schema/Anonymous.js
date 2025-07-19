import mongoose, { Schema } from "mongoose";

const AnonymousSchema = mongoose.Schema(
  {
    content: {
      type: String,
      required: true,
    },
    date: {
      type: Date,
      default: Date.now,
    },
    sender: {
      type: Schema.Types.ObjectId,
      ref: "users",
      default: null,
    },
    likes: {
      type: Number,
      default: 0,
    },
    views: {
      type: Number,
      default: 0,
    },
    colors: {
      type: String,
      defalt: "bg-blue-500",
    },
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("Anonymous", AnonymousSchema);
