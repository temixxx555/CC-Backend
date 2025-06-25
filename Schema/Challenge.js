import mongoose, { Schema } from "mongoose";

const challengeSchema = mongoose.Schema(
  {
    imageurl: {
      type: String,
      required: true,
    },
    posted_by: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: "users",
    },
    rank: {
      type: Number,
      default: 0,
    },
  },

  {
    timestamps:true,
  }
);

export default mongoose.model("challenges", challengeSchema);
