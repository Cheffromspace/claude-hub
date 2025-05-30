import express from 'express';
import { handleWebhook } from '../controllers/githubController';

const router = express.Router();

// GitHub webhook endpoint
router.post('/', handleWebhook as express.RequestHandler);

export default router;
