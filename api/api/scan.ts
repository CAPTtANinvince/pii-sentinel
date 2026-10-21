export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const { text } = req.body || {};

  if (!text || typeof text !== "string") {
    return res.status(400).json({
      error: "Text is required"
    });
  }

  return res.status(200).json({
    success: true,
    message: "Scan endpoint is working",
    textLength: text.length
  });
}
