#!/usr/bin/env node

const { spawnSync } = require('child_process')
const { request } = require('https')

const ORDERED_LEVELS = [
	'info',
	'low',
	'moderate',
	'high',
	'critical',
]

const npmSeverityToBitbucketSeverity = {
	info: 'LOW',
	low: 'LOW',
	moderate: 'MEDIUM',
	high: 'HIGH',
	critical: 'HIGH',
}

const bitbucket = {
	authentication: process.env.BITBUCKET_AUTH,
	baseUrl: process.env.BITBUCKET_BASE_URL || 'https://api.bitbucket.org/2.0/repositories/',
	commit: process.env.BITBUCKET_COMMIT,
	owner: process.env.BITBUCKET_REPO_OWNER,
	slug: process.env.BITBUCKET_REPO_SLUG,
}
if (Object.keys(bitbucket).filter(key => bitbucket[key]).length !== Object.keys(bitbucket).length) {
	console.error('Not all Bitbucket environment variables were set.')
	process.exit(1)
}

const reportName = process.env.BPR_NAME || 'Security: npm audit'
const reportId = process.env.BPR_ID || 'npmaudit'
const auditLevel = process.env.BPR_LEVEL || 'high'
const auditAnnotationLevel = process.env.BPR_LOG
const maxAuditOutputBufferSize = parseInt(process.env.BPR_MAX_BUFFER_SIZE, 10) || 1024 * 1024 * 10
if (!ORDERED_LEVELS.includes(auditLevel)) {
	console.error('Unsupported audit level.')
	process.exit(1)
}

const startTime = new Date().getTime()
const { stderr, stdout } = spawnSync('npm', [ 'audit', '--json' ], {
	maxBuffer: maxAuditOutputBufferSize,
})
if (stderr.toString()) {
	console.error('Could not execute the `npm audit` command.', stderr.toString())
	process.exit(1)
}
const audit = JSON.parse(stdout.toString())

const highestLevelIndex = ORDERED_LEVELS.reduce((value, level, index) => {
	return audit.metadata.vulnerabilities[level]
		? index
		: value
}, -1)

const shouldAddAnnotation = severity => {
	if (!auditAnnotationLevel) return true
	return ORDERED_LEVELS.indexOf(severity) >= ORDERED_LEVELS.indexOf(auditAnnotationLevel)
}

const push = (bitbucketUrl, data) => new Promise(resolve => {
	const url = new URL(bitbucketUrl)
	const options = {
		host: url.host,
		port: 443,
		path: url.pathname,
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': bitbucket.authentication,
		},
	}
	const req = request(options, response => {
		let body = ''
		response.setEncoding('utf8')
		response.on('data', chunk => {
			body += chunk.toString()
		})
		response.on('end', () => {
			if (response.statusCode < 200 || response.statusCode > 299) {
				console.error('Could not push report to Bitbucket.', response.statusCode, body)
				process.exit(1)
			} else {
				resolve()
			}
		})
	})
	req.write(JSON.stringify(data))
	req.end()
})

const baseUrl = [
	bitbucket.baseUrl,
	bitbucket.owner,
	'/repos/',
	bitbucket.slug,
	'/commits/',
	bitbucket.commit,
	'/reports/',
	reportId,
].join('')

const pushAllReports = async () => {
	await push(baseUrl, {
		title: reportName,
		details: 'Results of npm audit.',
		reporter: bitbucket.owner,
		result: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel)
			? 'PASS'
			: 'FAIL',
		data: [
			{
				title: 'Duration (seconds)',
				type: 'DURATION',
				value: Math.round((new Date().getTime() - startTime) / 1000),
			},
			{
				title: 'Dependencies',
				type: 'NUMBER',
				value: audit.metadata.dependencies.total === undefined
					? audit.metadata.totalDependencies
					: audit.metadata.dependencies.total,
			},
			{
				title: 'Safe to merge?',
				type: 'BOOLEAN',
				value: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel),
			},
		],
	})

	let annotationCount = 0
	for (const [ id, { via, effects } ] of Object.entries(audit.vulnerabilities)) {

		// These are libs that are effected by a different vulnerability, so we ignore them here.
		if (via && via.length && via.every(v => typeof v === 'string')) continue

		for (let { name, title, url, severity, range } of via) {
			if (title.startsWith(name)) {
				title = title.substring(name.length + 1)
			}
			// These are artifacts that I don't understand...
			if (!name || name === 'undefined') continue
			// Possibly ignore lower severity
			if (!shouldAddAnnotation(severity)) continue

			// From the Bitbucket API docs: https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Bworkspace%7D/%7Brepo_slug%7D/commit/%7Bcommit%7D/reports/%7BreportId%7D/annotations/%7BannotationId%7D#put
			// "a report can contain up to 1000 annotations"
			// If we get to that many, we'll just quit early.
			annotationCount++
			if (annotationCount >= 1000) break
			await push(
				`${baseUrl}/annotations/${reportId}-${id.replaceAll('/', '-')}`,
				{
					type: 'VULNERABILITY',
					message: `${name}: ${title}`,
					link: url,
					severity: npmSeverityToBitbucketSeverity[severity],
				},
			)
		}
	}
}

pushAllReports()
	.then(() => {
		console.log('Report successfully pushed to Bitbucket.')
		process.exit(0)
	})
