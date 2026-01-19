# FedRAMP 20x

A simple Powerpipe mod for visualizing Steampipe data.

## Quick Start

1. **Install Powerpipe** (if not already installed):
   ```bash
   brew install turbot/tap/powerpipe
   ```

2. **Start Steampipe** (to provide database access):
   ```bash
   steampipe service start
   ```

3. **Run the dashboard**:
   ```bash
   cd /path/to/fedramp_20x
   powerpipe server
   ```

4. **Open in browser**: Navigate to `http://localhost:9033`

## Project Structure

```
fedramp_20x/
├── mod.pp           # Mod definition
├── dashboard.pp     # Dashboard and query definitions
└── README.md        # This file
```

## Customizing the Dashboard

Edit `dashboard.pp` to customize the queries for your specific Steampipe plugins. The template includes:

- **Cards**: Summary metrics at the top
- **Charts**: Donut and line charts for visualization
- **Tables**: Detailed data views

### Common Dashboard Elements

| Element | Description |
|---------|-------------|
| `card` | Single metric display |
| `chart` | Donut, bar, line, column charts |
| `table` | Tabular data display |
| `container` | Layout grouping |
| `text` | Markdown text blocks |

## Resources

- [Powerpipe Documentation](https://powerpipe.io/docs)
- [Steampipe Plugins](https://hub.steampipe.io/plugins)
