const path = require('path');
// PDF generation
const PDFDocument = require('pdfkit');

// server.js
// server.js
const express = require('express');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const cors = require('cors');
const { URL } = require('url');
const app = express();
const PORT = process.env.PORT || 5000;
// Middleware
app.use(cors());
app.use(express.json());
// Serve frontend static files if present (optional)
const frontendPath = path.join(__dirname, '..', 'frontend');
// If the frontend directory exists, serve it
try {
	app.use(express.static(frontendPath));
	app.get('/', (req, res) => res.sendFile(path.join(frontendPath, 'index.html')));
} catch (err) {
	// ignore if frontend missing
}

// SSL Certificate Scanner Class
class SSLCertificateScanner {
	constructor() {
		this.weakSignatureAlgorithms = [
			'md5WithRSAEncryption',
			'sha1WithRSAEncryption',
			'md2WithRSAEncryption',
			'md4WithRSAEncryption'
		];
		this.minimumKeySize = 2048;
	}

	async scanCertificate(hostname, port = 443) {
		return new Promise((resolve, reject) => {
			const socket = tls.connect(port, hostname, {
				rejectUnauthorized: false,
				servername: hostname
			});
			socket.on('secureConnect', () => {
				try {
					const cert = socket.getPeerCertificate(true);
					const protocol = socket.getProtocol();
					const cipher = socket.getCipher();
					const result = this.analyzeCertificate(cert, protocol, cipher, hostname);
					socket.destroy();
					resolve(result);
				} catch (error) {
					socket.destroy();
					reject(error);
				}
			});
			socket.on('error', (error) => {
				reject(new Error(`Connection failed: ${error.message}`));
			});
			socket.setTimeout(10000, () => {
				socket.destroy();
				reject(new Error('Connection timeout'));
			});
		});
	}

	analyzeCertificate(cert, protocol, cipher, hostname) {
		// Try to extract richer public key / signature info using Node's X509Certificate when available
		let publicKeyAlgorithm = null;
		let publicKeySize = null;
		let signatureAlgorithm = cert.sigalg || cert.signatureAlgorithm || null;
		try {
			if (cert && cert.raw && crypto.X509Certificate) {
				const x509 = new crypto.X509Certificate(cert.raw);
				if (!signatureAlgorithm && x509.signatureAlgorithm) signatureAlgorithm = x509.signatureAlgorithm;
				try {
					const pub = x509.publicKey; // KeyObject
					if (pub && typeof pub.asymmetricKeyType === 'string') {
						publicKeyAlgorithm = pub.asymmetricKeyType.toUpperCase();
					}
					if (pub && typeof pub.asymmetricKeySize === 'number') {
						publicKeySize = pub.asymmetricKeySize; // bits
					}
				} catch (e) {
					// ignore key inspection errors
				}
			}
		} catch (e) {
			// ignore
		}

		const analysis = {
			hostname,
			certificate: {
				subject: cert.subject,
				issuer: cert.issuer,
				validFrom: cert.valid_from,
				validTo: cert.valid_to,
				fingerprint: cert.fingerprint,
				fingerprint256: cert.fingerprint256,
				serialNumber: cert.serialNumber,
				publicKeyAlgorithm,
				publicKeySize,
				signatureAlgorithm
			},
			connection: {
				protocol,
				cipher: cipher.name,
				cipherVersion: cipher.version
			},
			security: this.assessSecurity(cert, cipher),
			recommendations: []
		};
		analysis.recommendations = this.generateRecommendations(analysis);
		return analysis;
	}

	assessSecurity(cert, cipher) {
		const now = new Date();
		const validTo = new Date(cert.valid_to);
		const validFrom = new Date(cert.valid_from);
		const daysUntilExpiry = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
		const totalValidityDays = Math.ceil((validTo - validFrom) / (1000 * 60 * 60 * 24));
		const security = {
			isExpired: now > validTo,
			daysUntilExpiry,
			totalValidityDays,
			isWeakSignature: this.weakSignatureAlgorithms.includes(cert.sigalg),
			signatureAlgorithm: cert.sigalg,
			keySize: this.extractKeySize(cert),
			isWeakKey: false,
			selfSigned: cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN,
			riskLevel: 'LOW'
		};
		if (security.keySize && security.keySize < this.minimumKeySize) {
			security.isWeakKey = true;
		}
		security.riskLevel = this.calculateRiskLevel(security);
		return security;
	}

	extractKeySize(cert) {
		try {
			if (cert.pubkey && cert.pubkey.asymmetricKeySize) {
				return cert.pubkey.asymmetricKeySize; // bits
			}
			if (cert && cert.raw && crypto.X509Certificate) {
				const x509 = new crypto.X509Certificate(cert.raw);
				const pub = x509.publicKey;
				if (pub && typeof pub.asymmetricKeySize === 'number') {
					return pub.asymmetricKeySize; // bits
				}
			}
		} catch (e) {
			// ignore
		}
		return null;
	}

	calculateRiskLevel(security) {
		let riskScore = 0;
		if (security.isExpired) riskScore += 10;
		else if (security.daysUntilExpiry <= 7) riskScore += 8;
		else if (security.daysUntilExpiry <= 30) riskScore += 5;
		else if (security.daysUntilExpiry <= 90) riskScore += 2;
		if (security.isWeakSignature) riskScore += 7;
		if (security.isWeakKey) riskScore += 6;
		if (security.selfSigned) riskScore += 4;
		if (riskScore >= 10) return 'CRITICAL';
		if (riskScore >= 7) return 'HIGH';
		if (riskScore >= 4) return 'MEDIUM';
		return 'LOW';
	}

	generateRecommendations(analysis) {
		const recommendations = [];
		const security = analysis.security;
		if (security.isExpired) {
			recommendations.push({
				type: 'CRITICAL',
				message: 'Certificate has expired and needs immediate renewal',
				action: 'Renew SSL certificate immediately'
			});
		} else if (security.daysUntilExpiry <= 7) {
			recommendations.push({
				type: 'URGENT',
				message: `Certificate expires in ${security.daysUntilExpiry} days`,
				action: 'Renew SSL certificate as soon as possible'
			});
		} else if (security.daysUntilExpiry <= 30) {
			recommendations.push({
				type: 'WARNING',
				message: `Certificate expires in ${security.daysUntilExpiry} days`,
				action: 'Plan certificate renewal within the next week'
			});
		}
		if (security.isWeakSignature) {
			recommendations.push({
				type: 'HIGH',
				message: `Weak signature algorithm detected: ${security.signatureAlgorithm}`,
				action: 'Upgrade to SHA-256 or higher signature algorithm'
			});
		}
		if (security.isWeakKey) {
			recommendations.push({
				type: 'HIGH',
				message: `Weak key size detected: ${security.keySize} bits`,
				action: `Upgrade to at least ${this.minimumKeySize} bit RSA key or use ECDSA`
			});
		}
		if (security.selfSigned) {
			recommendations.push({
				type: 'MEDIUM',
				message: 'Self-signed certificate detected',
				action: 'Consider using a certificate from a trusted Certificate Authority'
			});
		}
		if (recommendations.length === 0) {
			recommendations.push({
				type: 'SUCCESS',
				message: 'Certificate appears to be secure',
				action: 'Continue monitoring certificate expiration dates'
			});
		}
		return recommendations;
	}

	async scanMultipleSites(sites) {
		const results = [];
		for (const site of sites) {
			try {
				const url = new URL(site.startsWith('http') ? site : `https://${site}`);
				const result = await this.scanCertificate(url.hostname, url.port || 443);
				results.push(result);
			} catch (error) {
				results.push({
					hostname: site,
					error: error.message,
					security: { riskLevel: 'UNKNOWN' }
				});
			}
		}
		return results;
	}
}
const scanner = new SSLCertificateScanner();

// Helper: generate a PDF from an existing scan result and stream to response
function generatePdfFromScan(res, result, hostnameForName) {
	try {
		const hostname = hostnameForName || (result && result.hostname) || 'report';
		res.setHeader('Content-Type', 'application/pdf');
		const safeHost = (hostname || 'report').replace(/[^a-z0-9.-]/gi, '_');
		res.setHeader('Content-Disposition', `attachment; filename="${safeHost}-ssl-report.pdf"`);

		const doc = new PDFDocument({ margin: 48, size: 'A4' });
		doc.pipe(res);

		const fmtDate = (d) => {
			try {
				if (!d) return 'N/A';
				const dt = new Date(d);
				return dt.toLocaleString('en-US', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
			} catch (e) { return String(d); }
		};

		function parseCipherDetailed(cipherStr) {
			if (!cipherStr) return null;
			const c = cipherStr;
			const info = { raw: c };
			if (c.includes('_')) {
				const parts = c.split('_');
				info.kdf = parts[0];
				info.cipher = parts.slice(1, parts.length - 1).join('_');
				info.hash = parts[parts.length - 1];
				const size = c.match(/(128|256|384)/);
				if (size) info.keyBits = size[0];
				info.description = `${info.kdf} with ${info.cipher} using ${info.hash} (TLS 1.3 style)`;
				return info;
			}
			if (c.includes('-')) {
				const parts = c.split('-');
				info.keyExchange = parts[0] || '';
				info.auth = parts[1] || '';
				const cipherPart = parts.slice(2, parts.length - 1).join('-') || parts[2] || '';
				info.cipher = cipherPart;
				info.hash = parts[parts.length - 1] || '';
				const size = c.match(/(128|256|384)/);
				if (size) info.keyBits = size[0];
				const keMap = {
					'ECDHE': 'Elliptic Curve Diffie-Hellman Ephemeral (provides forward secrecy)',
					'DHE': 'Diffie-Hellman Ephemeral (provides forward secrecy)',
					'RSA': 'RSA key exchange (no forward secrecy)'
				};
				const authMap = { 'RSA': 'RSA (signature/authentication)', 'ECDSA': 'ECDSA (signature/authentication)' };
				info.keyExchangeFriendly = keMap[info.keyExchange] || info.keyExchange;
				info.authFriendly = authMap[info.auth] || info.auth;
				info.description = `${info.keyExchange || ''} (${info.keyExchangeFriendly || ''}), auth=${info.auth}, cipher=${info.cipher}, hash=${info.hash}`;
				return info;
			}
			return { raw: c };
		}

		// Header
		doc.fontSize(20).fillColor('#0b2545').text('SSL/TLS Certificate Scan Report', { align: 'center' });
		doc.moveDown(0.3);
		doc.fontSize(11).fillColor('#0b2545').text(`Host: ${hostname}`, { align: 'center' });
		doc.moveDown();

		// Summary
		doc.fontSize(12).fillColor('#0a3358').text('Summary', { underline: true });
		doc.moveDown(0.2);
		doc.fontSize(10).fillColor('black');
		const sec = result.security || {};
		doc.text(`Scan time: ${fmtDate(new Date())}`);
		doc.text(`Overall risk: ${sec.riskLevel || 'N/A'}`);
		doc.text(`Expired: ${sec.isExpired ? 'Yes' : 'No'}`);
		doc.text(`Days until expiry: ${sec.daysUntilExpiry != null ? sec.daysUntilExpiry : 'N/A'}`);
		doc.moveDown();

		// Certificate details
		const cert = result.certificate || {};
		doc.font('Helvetica-Bold').fontSize(12).fillColor('#0a3358').text('Certificate Details');
		doc.moveDown(0.2);
		doc.font('Helvetica').fontSize(10).fillColor('black');
		const writeLabelValue = (label, value) => {
			doc.font('Helvetica-Bold').text(label + ':', { continued: true });
			doc.font('Helvetica').text(' ' + (value == null ? 'N/A' : String(value)));
		};
		writeLabelValue('Subject CN', cert.subject && cert.subject.CN);
		writeLabelValue('Subject (full)', JSON.stringify(cert.subject || {}, null, 0));
		writeLabelValue('Issuer', (cert.issuer && (cert.issuer.O || cert.issuer.CN)));
		writeLabelValue('Issuer (full)', JSON.stringify(cert.issuer || {}, null, 0));
		writeLabelValue('Valid From', fmtDate(cert.validFrom || cert.valid_from));
		writeLabelValue('Valid To', fmtDate(cert.validTo || cert.valid_to));
		writeLabelValue('Serial Number', cert.serialNumber);
		writeLabelValue('Fingerprint (SHA1)', cert.fingerprint);
		writeLabelValue('Fingerprint (SHA256)', cert.fingerprint256);
		writeLabelValue('Public Key Algorithm / Size', (cert.publicKeyAlgorithm || cert.pubkeyAlgorithm || (result.security && result.security.keySize) || 'N/A'));
		writeLabelValue('Signature Algorithm', cert.signatureAlgorithm || cert.sigalg || 'N/A');
		doc.moveDown();

		// Connection & cipher
		const conn = result.connection || {};
		doc.fontSize(12).text('Connection & Cipher Details', { underline: true });
		doc.moveDown(0.2);
		doc.fontSize(10).text(`Protocol negotiated: ${conn.protocol || 'N/A'}`);
		doc.text(`Raw cipher string: ${conn.cipher || 'N/A'}`);
		const parsed = parseCipherDetailed(conn.cipher || '');
		if (parsed) {
			doc.moveDown(0.1);
			doc.font('Helvetica-Bold').text('Parsed cipher components:');
			doc.moveDown(0.05);
			doc.font('Helvetica').fontSize(10);
			const bullet = (text) => { doc.circle(doc.x + 4, doc.y + 6, 2).fill('#0a3358').fillColor('black'); doc.text('  ' + text); };
			if (parsed.kdf) bullet(`KDF / TLS label: ${parsed.kdf}`);
			if (parsed.keyExchange) bullet(`Key exchange: ${parsed.keyExchange} — ${parsed.keyExchangeFriendly || ''}`);
			if (parsed.auth) bullet(`Authentication: ${parsed.auth} — ${parsed.authFriendly || ''}`);
			if (parsed.cipher) bullet(`Cipher algorithm: ${parsed.cipher}`);
			if (parsed.hash) bullet(`MAC / Hash: ${parsed.hash}`);
			if (parsed.keyBits) bullet(`Key length (bits): ${parsed.keyBits}`);
			if (parsed.description) bullet(`Description: ${parsed.description}`);
			let strength = 'Unknown';
			const h = (parsed.hash || '').toLowerCase();
			const kb = parsed.keyBits ? Number(parsed.keyBits) : 0;
			if (h.includes('sha384') || h.includes('sha512') || kb >= 256) strength = 'Strong';
			else if (h.includes('sha256') || kb >= 128) strength = 'Moderate';
			else strength = 'Weak / Deprecated';
			doc.moveDown(0.1);
			writeLabelValue('Estimated cipher strength', strength);
		}
		doc.moveDown();

		// Legend
		doc.fontSize(12).text('How to read the cipher and certificate info', { underline: true });
		doc.moveDown(0.2);
		doc.fontSize(10).text('Key Exchange: how the symmetric key is negotiated (ECDHE/DHE provide forward secrecy).');
		doc.text('Authentication: which algorithm is used to sign/authorize the handshake (RSA/ECDSA).');
		doc.text('Cipher: symmetric cipher and mode (e.g., AES_256_GCM).');
		doc.text('Hash/MAC: hashing or AEAD auth (e.g., SHA384).');
		doc.moveDown();

		// Recommendations
		doc.fontSize(12).text('Security Analysis & Recommendations', { underline: true });
		doc.moveDown(0.2);
		doc.fontSize(10);
		if (sec && sec.recommendations && sec.recommendations.length) {
			sec.recommendations.forEach((r, i) => {
				doc.text(`${i + 1}. [${r.type}] ${r.message}`);
				if (r.action) doc.text(`   Suggested action: ${r.action}`);
			});
		} else {
			doc.text('No specific recommendations found. Continue monitoring certificate expiry and follow standard TLS hardening guidance.');
		}
		doc.moveDown();

		// Raw JSON page
		doc.addPage();
		doc.fontSize(12).text('Raw Scan JSON (for debugging)', { underline: true });
		doc.moveDown(0.2);
		doc.font('Courier').fontSize(8).text(JSON.stringify(result, null, 2));

		doc.end();
	} catch (err) {
		console.error('PDF generation error', err);
		try { res.status(500).json({ error: 'Failed to generate PDF' }); } catch (e) {}
	}
}
// Routes
app.get('/api/health', (req, res) => {
	res.json({ status: 'OK', message: 'SSL Certificate Scanner API is running' });
});
app.post('/api/scan', async (req, res) => {
	try {
		const { hostname } = req.body;
		if (!hostname) {
			return res.status(400).json({
				error: 'Hostname is required'
			});
		}
		const result = await scanner.scanCertificate(hostname);
		res.json({ success: true, data: result });
	} catch (error) {
		res.status(500).json({
			success: false,
			error: error.message
		});
	}
});
app.post('/api/scan-multiple', async (req, res) => {
	try {
		const { sites } = req.body;
		if (!sites || !Array.isArray(sites) || sites.length === 0) {
			return res.status(400).json({
				error: 'Sites array is required'
			});
		}
		if (sites.length > 10) {
			return res.status(400).json({
				error: 'Maximum 10 sites allowed per request'
			});
		}
		const results = await scanner.scanMultipleSites(sites);
		res.json({ success: true, data: results });
	} catch (error) {
		res.status(500).json({
			success: false,
			error: error.message
		});
	}
});

// Server-side PDF report generation endpoint
// Accepts JSON: { hostname: 'example.com' }
app.post('/api/report', async (req, res) => {
  try {
	const { hostname } = req.body;
	if (!hostname) return res.status(400).json({ error: 'hostname is required' });
	const result = await scanner.scanCertificate(hostname);
	generatePdfFromScan(res, result, hostname);
  } catch (err) {
	console.error('Report generation error', err);
	res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Accept pre-computed scan JSON and return server-generated PDF without re-scanning
app.post('/api/report-from-data', async (req, res) => {
  try {
	const provided = req.body && (req.body.result || req.body);
	if (!provided) return res.status(400).json({ error: 'scan result JSON is required in body' });
	const result = provided.result || provided;
	const hostname = result.hostname || 'report';
	generatePdfFromScan(res, result, hostname);
  } catch (err) {
	console.error('report-from-data error', err);
	res.status(500).json({ error: 'Failed to generate PDF from provided data' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
	console.error(err.stack);
	res.status(500).json({
		success: false,
		error: 'Internal server error'
	});
});

app.listen(PORT, () => {
	console.log(`SSL Certificate Scanner API running on port ${PORT}`);
});

module.exports = app;
 