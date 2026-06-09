import express from "express";
import cors from "cors";
import scanRoutes from "./routes/scan.route";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("AI Security Engine Running");
});

app.use("/scan", scanRoutes);

const PORT = 3001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});