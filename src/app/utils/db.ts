import mongoose from "mongoose";
import config from "../config";
import app from "../../app";
import seedSuperAdmin from "../DB";

export async function connectDB() {
    try {
      await mongoose.connect(config.database_url as string);

      seedSuperAdmin();
      let server = app.listen(config.port, () => {
        console.log(`app is listening on port ${config.port}`);
        console.log(`click here ➡️  http://localhost:${config.port}`);
      });
      return server;
    } catch (err) {
      console.log(err);
    }
  }