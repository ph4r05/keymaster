module.exports = async ({ platform, isMainBranch, github, context, core, fetch  }) => {
    console.log('Owner:', context.repo.owner);
    console.log('Repo:', context.repo.repo);
    console.log('Ref:', context.ref);

    const fs = require('fs');
    const path = require('path');

    // Reading the spec file from the repository
    // Reading the 'keymaster.spec' file from the repository
    const versionFilePath = path.join(process.env.GITHUB_WORKSPACE, 'Makefile');
    const versionFileContent = fs.readFileSync(versionFilePath, 'utf8');
    const versionRegex = /^VERSION\??=\s*(\S+)\s*$/m;
    const versionMatch = versionFileContent.match(versionRegex);
    let version = '';
    let artifactoryFolder = '';
    let artifactoryBaseName = '';

    if (versionMatch && versionMatch[1]) {
        version = versionMatch[1].replace('-SNAPSHOT', '').replace('.rc', '').replace('-', '_');
        artifactoryFolder = version + (isMainBranch ? '' : '-SNAPSHOT')
        artifactoryBaseName = version + (isMainBranch ? '' : ('-SNAPSHOT'));  // artifactory automatically adds date and identifier, no need to add context.runId
        console.log('Version:', version, 'Artifactory folder:', artifactoryFolder, 'Artifactory base name:', artifactoryBaseName);
    } else {
        throw new Error('Version not found or parsing failed');
    }

    // Generate POM
    const pomName = `keymaster-${artifactoryBaseName}.pom`
    const pomPath = path.join(process.env.GITHUB_WORKSPACE, pomName);
    const file = fs.createWriteStream(pomPath);

    file.write('<?xml version="1.0" encoding="UTF-8"?>\n');
    file.write('<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd" xmlns="http://maven.apache.org/POM/4.0.0"\n');
    file.write('    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n');
    file.write('  <modelVersion>4.0.0</modelVersion>\n');
    file.write('  <groupId>com.purestorage</groupId>\n');
    file.write('  <artifactId>keymaster</artifactId>\n');
    file.write(`  <version>${artifactoryFolder}</version>\n`);
    file.write('  <packaging>pom</packaging>\n');
    file.write('</project>\n');
    file.end(); // Close the stream

    core.setOutput('version', version);
    core.setOutput('artifactoryFolder', artifactoryFolder);
    core.setOutput('artifactoryBaseName', artifactoryBaseName);
    core.setOutput('pomName', pomName);

    // Artifactory upload
    const username = process.env.ORG_GRADLE_PROJECT_artifactoryUsername;
    const password = process.env.ORG_GRADLE_PROJECT_artifactoryPassword;
    const artifactoryUrl = process.env.ARTIFACTORY_URL;
    const artifactoryUpload = async (filePath, destinationPath, allowFail = false) => {
        const fileContent = fs.readFileSync(filePath, {encoding: 'base64'});
        const url = `${artifactoryUrl}/${artifactoryFolder}/${destinationPath}`;
        console.log(`Uploading ${filePath} to ${url}`);

        const response = await fetch(url, {
            method: 'PUT',
            headers: {
                'Authorization': 'Basic ' + btoa(username + ':' + password),
                'Content-Type': 'application/octet-stream'
            },
            body: Buffer.from(fileContent, 'base64')
        });

        const responseText = await response.text();
        if (!response.ok) {
            const message = `Failed to upload ${destinationPath}: ${response.status} ${response.statusText}; ${responseText}`;
            if (!allowFail) {
                throw new Error(message);
            } else {
                console.log(message);
            }
        } else {
            console.log(`Upload successful ${destinationPath}: ${response.status} ${response.statusText}; ${responseText}`);
        }
    }

    const findFiles = (directory, pattern) => {
        return fs.readdirSync(directory).filter(file => pattern.test(file));
    }

    // Upload main zip
    await artifactoryUpload(`artifacts/keymaster-${platform}.zip`, `keymaster-${artifactoryBaseName}-${platform}.zip`);

    // POM can fail as it can be already uploaded and also is not essential for keymaster operation as it is not a java package
    await artifactoryUpload(pomName, pomName, true);
};
