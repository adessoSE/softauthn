plugins {
    `java-library`
    `maven-publish`
}

group = "de.adesso.softauthn"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
    implementation("com.augustcellars.cose:cose-java:0.9.7")
    api("com.yubico:webauthn-server-core:2.0.0")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}


publishing {

    publications {
        create<MavenPublication>("main") {
            from(components["java"])
        }
    }
}
