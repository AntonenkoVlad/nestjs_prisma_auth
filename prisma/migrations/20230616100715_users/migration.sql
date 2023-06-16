/*
  Warnings:

  - You are about to drop the column `verified` on the `users` table. All the data in the column will be lost.
  - Added the required column `userId` to the `tokens` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "tokens" ADD COLUMN     "userId" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "users" DROP COLUMN "verified",
ADD COLUMN     "emailVerified" BOOLEAN NOT NULL DEFAULT false;

-- AddForeignKey
ALTER TABLE "tokens" ADD CONSTRAINT "tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
