
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Application, NextFunction, Request, Response } from 'express';
import config from './app/config';
import globalErrorHandler from './app/middlewares/globalErrorhandler';
import router from './app/routes';

const app: Application = express();

//parsers
app.use(express.json({ limit: '50mb' })); //its for the body parser for cloudinary 
app.use(cookieParser());

// app.use(cors({ origin: config.cors_origin, credentials: true })); // for production and specific origin
app.use(cors()); // for local development

// application routes
app.use('/api/v1', router);

app.get('/', (req: Request, res: Response) => {
    res.send('Hi Next Level Developer !');
});

app.use(globalErrorHandler);

//Not Found
app.use((req: Request, res: Response, next: NextFunction) => {
    const err = new Error(`Route ${req.originalUrl} not found`) as any;
    err.statusCode = 404;
    next(err);
});

export default app;
