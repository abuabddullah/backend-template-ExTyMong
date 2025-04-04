import { IncomingMessage, Server, ServerResponse } from "http";
import { connectDB } from "./app/utils/db";


let server: Server<typeof IncomingMessage, typeof ServerResponse>

const connectedServer = async () => {
    const serverInstance = await connectDB();
    if (!serverInstance) {
        console.error('Failed to start server');
        process.exit(1);
    }
    server = serverInstance;
}

connectedServer();

process.on('unhandledRejection', (err) => {
    console.log(`😈 unahandledRejection is detected , shutting down ...`, err);
    if (server) {
        server.close(() => {
            process.exit(1);
        });
    }
    process.exit(1);
});

process.on('uncaughtException', () => {
    console.log(`😈 uncaughtException is detected , shutting down ...`);
    process.exit(1);
});
