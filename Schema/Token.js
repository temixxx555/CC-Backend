import mongoose, { Schema } from "mongoose";

const tokenSchema = mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Token", tokenSchema);
