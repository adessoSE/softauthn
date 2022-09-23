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
    api("com.yubico:webauthn-server-core:2.0.0")
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).tags("apiNote:a:API Note:", "implNote:a:Implementation Note:")
}

val javadocJar = tasks.create<Jar>("javadocJar") {
    dependsOn(tasks.javadoc)
    archiveClassifier.set("javadoc")
    from(tasks.javadoc.get().destinationDir)
}

val sourcesJar = tasks.create<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    from(sourceSets[SourceSet.MAIN_SOURCE_SET_NAME].allSource)
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
            artifact(sourcesJar)
            artifact(javadocJar)
        }
    }
}
