const functions = require('@google-cloud/functions-framework');
const { RecaptchaEnterpriseServiceClient } = require('@google-cloud/recaptcha-enterprise');

functions.http('handler', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');

  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'GET');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
    res.status(204).send('');
  } else {
    const projectId = req.query?.projectId || null;
    const siteKey = req.query?.siteKey || null;
    const token = req.query?.token || null;
    const action = req.query?.action || null;

    if (!projectId) throw new Error(`The parameter projectId must be provided.`);
    if (!siteKey) throw new Error(`The parameter siteKey must be provided.`);
    if (!token) throw new Error(`The parameter token must be provided.`);
    if (!action) throw new Error(`The parameter action must be provided.`);

    const score = await createAssessment(projectId, siteKey, token, action);

    res.send({ score });
  }
});

/**
  * Create an assessment to analyze the risk of a UI action.
  *
  * projectId: Your Google Cloud Project ID.
  * recaptchaSiteKey: The reCAPTCHA key associated with the site/app
  * token: The generated token obtained from the client.
  * recaptchaAction: Action name corresponding to the token.
  */
async function createAssessment(projectId, recaptchaKey, token, recaptchaAction) {
  // Create the reCAPTCHA client.
  const client = new RecaptchaEnterpriseServiceClient();
  const projectPath = client.projectPath(projectId);

  // Build the assessment request.
  const request = ({
    assessment: {
      event: {
        token: token,
        siteKey: recaptchaKey,
      },
    },
    parent: projectPath,
  });

  const [response] = await client.createAssessment(request);
  client.close();

  // Check if the token is valid.
  if (!response.tokenProperties.valid) {
    console.log(`The CreateAssessment call failed because the token was: ${response.tokenProperties.invalidReason}`);
    return null;
  }

  // Check if the expected action was executed.
  // The `action` property is set by user client in the grecaptcha.enterprise.execute() method.
  if (response.tokenProperties.action === recaptchaAction) {
    // Get the risk score and the reason(s).
    // For more information on interpreting the assessment, see:
    // https://cloud.google.com/recaptcha-enterprise/docs/interpret-assessment
    console.log(`The reCAPTCHA score is: ${response.riskAnalysis.score}`);
    response.riskAnalysis.reasons.forEach((reason) => {
      console.log(reason);
    });

    return response.riskAnalysis.score;
  } else {
    console.log("The action attribute in your reCAPTCHA tag does not match the action you are expecting to score");
    return null;
  }
}