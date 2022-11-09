plugins {
    `java-library`
    `maven-publish`
    signing
}

group = "io.github.adessose"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.0")
    implementation("com.augustcellars.cose:cose-java:1.1.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.14.0-rc2")
    api("com.yubico:webauthn-server-core:2.1.0")
}

java {
    withSourcesJar()
    withJavadocJar()
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).tags("apiNote:a:API Note:", "implNote:a:Implementation Note:")
}

publishing {

    publications {
        create<MavenPublication>("main") {
            pom {
                scm {
                    url.set("https://github.com/adessoSE/softauthn")
                }
                licenses {
                    license {
                        name.set("MIT")
                        url.set("https://mit-license.org")
                    }
                }
                developers {
                    developer {
                        organization.set("adesso SE")
                        organizationUrl.set("https://adesso.de")
                    }
                }
            }
            from(components["java"])
        }
    }

    repositories {
        maven {
            name = "OSSRH"
            setUrl("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2")
            credentials {
                username = project.findProperty("osshrUsername") as String? ?: return@credentials
                password = project.findProperty("osshrPassword") as String? ?: return@credentials
            }
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications)
}