import mongoose, { Schema } from "mongoose";

const notificationSchema = mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["like", "comment", "reply", "followed", "info"],
      required: true,
    },
    blog: {
      type: Schema.Types.ObjectId,
      default: null,
      ref: "blogs",
    },
    notification_for: {
      type: Schema.Types.ObjectId,
      default: null,
      ref: "users",
    },
    user: {
      type: Schema.Types.ObjectId,
      default: null,
      ref: "users",
    },
    title: {
      type: String,
      default: "",
    },
    message: {
      type: String,
      default: "",
    },
    comment: {
      type: Schema.Types.ObjectId,
      ref: "comments",
      default: null,
    },
    reply: {
      type: Schema.Types.ObjectId,
      ref: "comments",
      default: null,
    },
    replied_on_comment: {
      type: Schema.Types.ObjectId,
      ref: "comments",
      default: null,
    },
    seen: {
      type: Boolean,
      default: false,
    },
    isGlobal: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

export default mongoose.model("notification", notificationSchema);
