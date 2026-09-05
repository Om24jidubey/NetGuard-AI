from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_report(data, output_path):

    doc = SimpleDocTemplate(output_path)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "NetGuard AI Security Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 12))

    elements.append(
        Paragraph(
            f"Records Analyzed: {data['total_analyzed']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Threats Detected: {data['anomalies_found']}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Network Health: {data['network_health']}%",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Attack Distribution",
            styles["Heading2"]
        )
    )

    for attack in data["attack_distribution"]:

        elements.append(
            Paragraph(
                f"{attack['name']} : {attack['value']}",
                styles["BodyText"]
            )
        )

    doc.build(elements)

    return output_path