const backend = process.env.BACKEND_API_URL || "http://127.0.0.1:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [{ source: "/backend/:path*", destination: `${backend}/:path*` }];
  }
};

export default nextConfig;
