plugins {
    `java-library`
    `maven-publish`
}

group = "de.adesso"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.0")
    implementation("com.augustcellars.cose:cose-java:1.1.0")
    api("com.yubico:webauthn-server-core:2.1.0")
}

configure<JavaPluginExtension> {
    withSourcesJar()
    withJavadocJar()
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
}
