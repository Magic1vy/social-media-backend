import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => {
    try {
        let token = req.header("Authorization");

        if (!token) {
            return res.status(403).send("Access Denied");
        }

        if (token.startsWith("Bearer ")) {
            token = token.slice(7, token.length).trimLeft();
        }

        if (!token) {
            return res.status(403).send("Access Denied");
        }

        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;

        next();

    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ err: "Invalid or expired token" });
        }

        return res.status(500).json({ err: err.message });
    }
}
