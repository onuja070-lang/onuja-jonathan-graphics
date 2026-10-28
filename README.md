# Onuja Jonathan Portfolio

Portfolio site with persistent design uploads, owner sign-in, customer accounts, and chat.

## Requirements

- Node.js 22.5 or newer
- A unique owner password (at least 10 characters; choose a longer password for public deployment)
- A random session secret (at least 32 characters)

## Start locally

1. Copy `.env.example` to `.env` and set `OWNER_PASSWORD` and `SESSION_SECRET` to private values.
2. In this folder, run `npm install`.
3. Run `npm start` and open `http://localhost:3000`.
4. Open `http://localhost:3000/studio` to sign in, upload or remove designs, and reply to customer conversations. The owner sign-in is kept off the public homepage.
5. Customers can create an account from the Customer account section. Their password is stored as a scrypt hash; their contact profile and chat history are kept in SQLite.

Project records and messages are stored in `data/portfolio.sqlite`; uploaded image files are stored in `uploads/`. Back up both before moving the site. Keep `.env`, `data/`, and private owner credentials out of public repositories. The included `render.yaml` configures a Render web service with a persistent disk. Render requires a paid Starter instance for persistent disks; set `OWNER_PASSWORD` and `SESSION_SECRET` in the service environment when creating it. The owner cookie uses HTTPS automatically in production.