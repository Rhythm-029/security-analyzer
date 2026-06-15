import express from "express";
import cors from "cors";
import path from "path";
import scanRoutes from "./routes/scan.route";
import { getDefaultRepositoryPath } from "./config/repository.config";

const app = express();

app.use(cors());
app.use(express.json());

// Serve static assets from frontend directory
app.use(express.static(path.join(__dirname, "../../frontend")));

app.use("/scan", scanRoutes);

const PORT = 3001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});