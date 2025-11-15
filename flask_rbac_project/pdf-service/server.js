const express = require('express');
const puppeteer = require('puppeteer');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json({ limit: '10mb' }));

app.post('/generate-pdf', async (req, res) => {
  const { html } = req.body;
  if (!html) {
    return res.status(400).send('Missing HTML content');
  }
  try {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4' });

    await browser.close();

    res.contentType('application/pdf');
    res.send(pdfBuffer);
  } catch (err) {
    console.error('PDF generation error:', err);
    res.status(500).send('Error generating PDF');
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`PDF microservice listening on port ${port}`);
});