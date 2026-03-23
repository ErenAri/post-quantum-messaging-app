import java.util.Locale

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val repoRoot = rootProject.rootDir.resolve("../..").canonicalFile
val generatedUniFFIDir = file("$buildDir/generated/uniffi/kotlin")

android {
    namespace = "com.pqmsg.demo"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.pqmsg.demo"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField("String", "TLS_PIN_SHA256", "\"\"")
        buildConfigField("String", "TLS_BACKUP_PIN_SHA256", "\"\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            buildConfigField("boolean", "ALLOW_CLEARTEXT_DEMO", "true")
            manifestPlaceholders["usesCleartextTraffic"] = "true"
        }
        release {
            isMinifyEnabled = false
            buildConfigField("boolean", "ALLOW_CLEARTEXT_DEMO", "false")
            manifestPlaceholders["usesCleartextTraffic"] = "false"
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    sourceSets {
        getByName("main") {
            java.srcDir(generatedUniFFIDir)
            jniLibs.srcDir("src/main/jniLibs")
        }
    }
    buildFeatures {
        buildConfig = true
    }
}

val hostLibName = when {
    System.getProperty("os.name").lowercase(Locale.US).contains("win") -> "pqmsg_android.dll"
    System.getProperty("os.name").lowercase(Locale.US).contains("mac") -> "libpqmsg_android.dylib"
    else -> "libpqmsg_android.so"
}
val hostLibPath = repoRoot.resolve("target/debug/$hostLibName")

tasks.register<Exec>("buildRustHostLibrary") {
    workingDir = repoRoot
    commandLine("cargo", "build", "-p", "pqmsg-android")
}

tasks.register<Exec>("generateUniFFIBindings") {
    dependsOn("buildRustHostLibrary")
    workingDir = repoRoot
    doFirst {
        generatedUniFFIDir.mkdirs()
    }
    commandLine(
        "cargo",
        "run",
        "-p",
        "pqmsg-android",
        "--bin",
        "uniffi-bindgen",
        "--",
        "generate",
        "--library",
        hostLibPath.absolutePath,
        "--language",
        "kotlin",
        "--out-dir",
        generatedUniFFIDir.absolutePath
    )
}

tasks.named("preBuild").configure {
    dependsOn("generateUniFFIBindings")
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-gson:2.11.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("net.zetetic:sqlcipher-android:4.14.0@aar")
    implementation("androidx.sqlite:sqlite:2.6.2")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}
