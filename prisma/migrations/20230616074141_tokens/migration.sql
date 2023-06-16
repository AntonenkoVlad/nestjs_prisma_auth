-- CreateEnum
CREATE TYPE "TokenEnum" AS ENUM ('RESET_PASSWORD', 'EMAIL_VERIFICATION');

-- CreateTable
CREATE TABLE "tokens" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "type" "TokenEnum" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tokens_pkey" PRIMARY KEY ("id")
);
