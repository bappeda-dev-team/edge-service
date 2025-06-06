# ---- BUILD STAGE ----
FROM gradle:8.4-jdk17 AS build
WORKDIR /app

# Copy only what's needed first to leverage Docker cache
COPY build.gradle.kts settings.gradle.kts ./
COPY gradle ./gradle
RUN gradle build --no-daemon || return 0

# Copy the rest and build the app
COPY . .
RUN gradle bootJar --no-daemon

# ---- RUNTIME STAGE ----
FROM eclipse-temurin:17-jre as runtime
WORKDIR /app

# Copy the JAR from build stage
COPY --from=build /app/build/libs/*.jar app.jar

# Run the app
ENTRYPOINT ["java", "-jar", "app.jar"]
