###############################################
# ---------- Build Stage ----------
###############################################

# Use Maven with OpenJDK 18 as the base image for building the project.
# This ensures we have both JDK (for compilation) and Maven (for dependency management).
FROM maven:3.8.7-openjdk-18 AS build

# Set working directory inside the container where the build process will run.
WORKDIR /build

# Copy Maven's pom.xml first (without source code).
# This allows Docker to leverage build caching – dependencies won’t be re-downloaded unless pom.xml changes.
COPY pom.xml .

# Download all project dependencies ahead of time (go-offline mode).
# This speeds up builds since Maven won’t need to fetch dependencies again when the code is copied.
RUN mvn dependency:go-offline

# Copy actual source code into container after dependencies are already cached.
COPY src ./src

# Build the JAR file, skipping tests for faster builds.
# The compiled JAR will be located under /build/target/
RUN mvn clean package -DskipTests


###############################################
# ---------- Runtime Stage ----------
###############################################

# Use a lightweight JDK 17 image for running the application.
# Amazon Corretto is a free, production-ready distribution of OpenJDK.
FROM amazoncorretto:17

# Declare build-time arguments:
# - PROFILE allows selecting the Spring Boot profile (e.g., dev, test, prod).
# - APP_VERSION allows overriding the app version at build time if needed.
ARG PROFILE=dev
ARG APP_VERSION=1.0.1

# Set working directory for the running application.
WORKDIR /app

# Copy the built JAR file from the "build" stage into /app directory of runtime container.
COPY --from=build /build/target/book-network-*.jar /app/

# Attempt to dynamically extract JAR version from the filename.
# - "ls /app | grep *.jar" lists jar files.
# - "awk 'NR==2...'" tries to parse version number from file name.
# ⚠️ NOTE: 'NR==2' might cause issues if there is only one JAR file (it would skip it).
RUN APP_VERSION=$(ls /app | grep *.jar | awk 'NR==2{split($0,a,"-"); print a[3]}' | awk '{sub(/.jar$/,"")}1') \
    && echo "Building container with BSN v-$version"

# Expose application port (Spring Boot app listens on 8088).
EXPOSE 8088

# Set environment variables for runtime configuration:
# - DB_URL: PostgreSQL connection string (host is a container named postgres-sql-bsn).
# - MAILDEV_URL: Mail server (default localhost).
# - ACTIVE_PROFILE: Spring Boot active profile (default: dev).
# - JAR_VERSION: Application JAR version (passed from build args).
ENV DB_URL=jdbc:postgresql://postgres-sql-bsn:5432/book_social_network
ENV MAILDEV_URL=localhost
ENV ACTIVE_PROFILE=${PROFILE}
ENV JAR_VERSION=${APP_VERSION}

# Run the Spring Boot application.
# - "-Dspring.profiles.active" selects the Spring profile (dev/test/prod).
# - "-Dspring.datasource.url" injects the database connection string.
# The command starts the correct JAR version dynamically.
CMD java -jar -Dspring.profiles.active=${ACTIVE_PROFILE} -Dspring.datasource.url=${DB_URL} book-network-${JAR_VERSION}.jar
