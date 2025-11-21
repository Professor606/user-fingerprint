# Browser Fingerprinting Demo

A single-page educational project that demonstrates what information JavaScript can collect from users who simply click a link. This project reveals the extensive data websites can gather for tracking, analytics, or access control purposes.

## What This Project Does

When a user visits this page, it automatically collects comprehensive browser and device information using only client-side JavaScript. This demonstrates that:

- **Any website can collect this data** without special permissions
- **99% of web users** are vulnerable since JavaScript is enabled by default
- **Even Tor users** are exposed if JavaScript isn't disabled
- **Website owners receive this data** on their servers from every visitor

## Information Collected

### Browser & System Information
- User Agent string
- Platform and operating system
- Hardware capabilities (CPU cores, memory)
- Java status
- Do Not Track preference

### Screen & Display
- Screen resolution and available space
- Color depth and pixel depth
- Window dimensions
- Device pixel ratio

### Localization
- Preferred language
- All supported languages
- Timezone
- Local time

### Network & Location
- IP address
- Approximate geolocation (city, region, country)
- ISP information
- Coordinates

*Note: IP-based geolocation requires an API token from [ipinfo.io](https://ipinfo.io)*

## The 6-Hash Tracking System

Instead of creating a single fingerprint hash (which changes when users modify any setting), this project generates **six independent hashes** for more robust tracking:

1. **Browser Fingerprint** - User agent, platform
2. **Device Fingerprint** - Hardware specs, screen properties and pixel ratios
3. **Languages Fingerprint** - Language preferences
4. **Window Fingerprint** - Browser window dimensions
5. **Timezone Fingerprint** - Timezone and local time patterns
6. **IP Fingerprint** - IP address and location data

## The log system

Every request sent to the server is saved in `server.log` with timestamp, client hashes, unique `userID` number and `networkID` number based on the client hash info.

### Why Multiple Hashes?

If a user tries to evade tracking by:
- Using a VPN (changes IP) → Other 5 hashes remain the same
- Changing user agent → Other 5 hashes remain the same
- Resizing the browser window → Other 5 hashes remain the same

This multi-hash approach allows websites to still identify users even when they attempt to mask their identity by changing individual attributes.

## Setup

1. Clone this repository
```bash
git clone https://github.com/professor606/user-fingerprint.git
cd user-fingerprint
touch .env
```

2. Get an API token from [ipinfo.io](https://ipinfo.io/signup)

3. Define your API token in the `.env` file:
```bash
IPINFO_TOKEN=YOUR_SECRET_TOKEN
```

4. Specify the desired server port in the .env file:
```bash
PORT=3000
```

5. Install dependencies
```bash
npm install
```

6. Start the server
```bash
npm run start
```

## Defense Against Tracking

To minimize fingerprinting:
- Use privacy-focused browsers (Tor Browser with JavaScript disabled, Brave)
- Enable fingerprinting protection in browser settings
- Use browser extensions that spoof fingerprints
- Disable JavaScript on sensitive sites
- Use multiple browser profiles for different activities

## Use Cases (Educational)

Understanding browser fingerprinting is important for:
- **Security professionals** testing website vulnerabilities
- **Privacy researchers** studying tracking techniques
- **Web developers** implementing ethical analytics
- **Users** learning about their digital footprint

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- IP geolocation data provided by [ipinfo.io](https://ipinfo.io)
- Inspired by privacy research and electronic frontier advocacy

## Disclaimer

This project is intended for **educational purposes only**. It demonstrates browser fingerprinting techniques to raise awareness about online privacy. Users should not use this tool to track individuals without their knowledge or consent. Always respect privacy laws and regulations in your jurisdiction.

---

**Remember:** Protect privacy, not violate it.