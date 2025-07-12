import mongoose, { Schema } from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    sender: {
      type: Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
    recipient: {
      type: Schema.Types.ObjectId,
      ref: "users",
      required: false,
    },
    messageType: {
      type: String,
      // also add voice
      enum: ["text", "file"],
      required: true,
    },
     room: {
      type: String, // e.g., "global", "group-123"
      required: false,
    },
    content: {
      type: String,
      required: function () {
        return this.messageType === "text";
      },
    },
    fileUrl: {
      type: String,
      required: function () {
        return this.messageType === "file";
      },
    },
    isRead: { type: Boolean, default: false },
    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

export default mongoose.model("Messages", messageSchema);
